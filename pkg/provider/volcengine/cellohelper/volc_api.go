// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package cellohelper

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	v1 "k8s.io/api/core/v1"
	k8sErr "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"

	"github.com/volcengine/cello/pkg/backoff"
	"github.com/volcengine/cello/pkg/config"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
	"github.com/volcengine/cello/pkg/tracing"
	ip2 "github.com/volcengine/cello/pkg/utils/ip"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/types"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "volc"})

const (
	ENITypePrimary   = "primary"
	ENITypeSecondary = "secondary"
	ENITypeTrunk     = "trunk"

	ENIStatusAvailable = "Available"
	ENIStatusInuse     = "InUse"

	eniLeakedTime = 5 * time.Minute
	maxPageSize   = 100
)

type VolcAPI interface {

	// AllocENI creates an ENI and attaches it to the instance
	AllocENI(subnet string, securityGroups []string, trunk bool, ipCnt int) (*types.ENI, error)

	// FreeENI detaches ENI interface and deletes it
	FreeENI(eniID string) error

	// GetENI get eni by mac from metadata
	GetENI(mac string) (*types.ENI, error)

	// GetAttachedENIs return all attached eni created by cello
	GetAttachedENIs(withTrunk bool) ([]*types.ENI, error)

	GetSecondaryENIMACs() ([]string, error)

	// GetENIIPList returns the IPs for a given ENI from instance metadata service
	GetENIIPList(eniMac string) ([]net.IP, []net.IP, error)

	// AllocIPAddresses allocates numIPs IP addresses on an ENI
	AllocIPAddresses(eniID, eniMac string, v4Cnt, v6Cnt int) ([]net.IP, []net.IP, error)

	// DeallocIPAddresses deallocates the IP addresses from an ENI
	DeallocIPAddresses(eniID, eniMac string, ipv4s, ipv6s []net.IP) error

	// GetInstanceLimit return instance InstanceLimits
	GetInstanceLimit() (*InstanceLimits, error)

	// GetTotalAttachedEniCnt return count of all eni attached to instance, even across accounts
	GetTotalAttachedEniCnt() (int, error)
}

type VolcApiImpl struct {
	ipFamily types.IPFamily
	// metadata info
	InstanceMetadataGetter
	privateIPMutex sync.RWMutex
	// ec2
	ec2Client   ec2.EC2
	metadataSvc metadata.EC2MetadataWrapper
	// TODO: rm while metadata support ipv6
	subnetMgr SubnetManager
	tags      map[string]string
}

// deleteENI delete an ENI with available status.
func (e *VolcApiImpl) deleteENI(eniID string) error {
	var err error
	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("delete eni failed, %v", err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventReleaseResourceFailed, fmtErr)
		}
	}()

	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
		_, err = e.ec2Client.DeleteNetworkInterface(&vpc.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: volcengine.String(eniID),
		})
		errCodes := &apiErr.OpenApiErrCodeChain{}
		if err == nil {
			return true, nil
		}
		if errCodes.WithErrCodes(apiErr.InvalidEniIdNotFound, apiErr.InvalidEniInstanceMismatch).ErrChainEqual(err) {
			log.Warnf("DeleteNetworkInterface %s occur err: %v, ignore", eniID, err.(apiErr.APIRequestError).ErrorCode())
			return true, nil
		}
		errCodes = &apiErr.OpenApiErrCodeChain{}
		if errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidEniInvalidStatus, apiErr.InvalidVpcInvalidStatus).ErrChainEqual(err) {
			return false, err
		}
		return false, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		return err
	}
	log.Infof("Deleted eni %s", eniID)
	return nil
}

// freeENI detach and delete an ENI.
func (e *VolcApiImpl) freeENI(eniID string, sleepDelayAfterDetach time.Duration) error {
	log.Debugf("free ENI")
	var err error

	defer func() {
		if err != nil {
			log.Errorf("Free eni failed, %v", err)
		}
	}()

	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
		_, err = e.ec2Client.DetachNetworkInterface(&vpc.DetachNetworkInterfaceInput{
			InstanceId:         volcengine.String(e.GetInstanceId()),
			NetworkInterfaceId: volcengine.String(eniID),
		})

		errCodes := &apiErr.OpenApiErrCodeChain{}
		errCodes.WithErrCodes(apiErr.InvalidEniIdNotFound, apiErr.InvalidEniInstanceMismatch)
		if err == nil {
			return true, nil
		}
		if errCodes.ErrChainEqual(err) {
			log.Warnf("Detach networkInterface %s occur err: %s, ignore", eniID, err.(apiErr.APIRequestError).ErrorCode())
			return true, nil
		}
		errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus,
			apiErr.InvalidEniIdNotFound, apiErr.InvalidEniInstanceMismatch,
			apiErr.InvalidEniInvalidStatus)

		if err == nil || errCodes.ErrChainEqual(err) {
			return false, err
		}
		return false, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("FreeENI: detach network interface failed: %s", err.Error())
		fmtErr := fmt.Sprintf("detach eni failed, %v", err)
		_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventReleaseResourceFailed, fmtErr)
		return fmt.Errorf("free ENI failed while detach: %s", err.Error())
	}

	time.Sleep(sleepDelayAfterDetach)

	err = e.deleteENI(eniID)
	return nil
}

// createENI create an ENI and make sure it's status is available, ipv4Cnt.
func (e *VolcApiImpl) createENI(subnet string, securityGroups []string, trunk bool, ipv4Cnt, ipv6Cnt int) (string, error) {
	var eniResponse *vpc.CreateNetworkInterfaceOutput
	var err error
	instanceType := ENITypeSecondary
	if trunk {
		instanceType = ENITypeTrunk
	}
	req := &ec2.CreateNetworkInterfaceInput{
		SubnetId:         volcengine.String(subnet),
		SecurityGroupIds: volcengine.StringSlice(securityGroups),
		Description:      volcengine.String(eniDescription),
		Tags:             BuildTagsForCreateNetworkInterfaceInput(e.tags),
		Type:             volcengine.String(instanceType),
	}
	// todo: ipv6
	if ipv4Cnt > 1 {
		req.SecondaryPrivateIpAddressCount = volcengine.Int64(int64(ipv4Cnt - 1))
	}
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
		eniResponse, err = e.ec2Client.CreateNetworkInterface(req)
		errCodes := &apiErr.OpenApiErrCodeChain{}
		if err == nil || errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus, apiErr.InsufficientIpInSubnet,
			apiErr.QuotaExceededSecurityGroupIp, apiErr.QuotaExceededEni, apiErr.QuotaExceededEniSecurityGroup).
			ErrChainEqual(err) {
			return true, err
		}
		return false, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("Failed to CreateNetworkInterface %s", err.Error())
		return "", fmt.Errorf("failed to create network interface: %s", err.Error())
	}

	eniID := volcengine.StringValue(eniResponse.NetworkInterfaceId)
	var eniAttributes *ec2.DescribeNetworkInterfaceAttributesOutput
	werr = wait.ExponentialBackoff(backoff.BackOff(backoff.APIStatusWait), func() (bool, error) {
		eniAttributes, err = e.ec2Client.DescribeNetworkInterfaceAttributes(&vpc.DescribeNetworkInterfaceAttributesInput{
			NetworkInterfaceId: eniResponse.NetworkInterfaceId,
		})
		return err == nil && volcengine.StringValue(eniAttributes.Status) == ENIStatusAvailable, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		return "", fmt.Errorf("eni %s status has not become %s: %s", eniID, ENIStatusAvailable, err.Error())
	}

	defer func() {
		if err != nil {
			err = e.deleteENI(eniID)
			if err != nil {
				log.Errorf("rollback create eni due to %v", err)
			}
		}
	}()

	_, _, err = e.AllocIPAddresses(eniID, volcengine.StringValue(eniAttributes.MacAddress), 0, ipv6Cnt)
	if err != nil {
		return "", fmt.Errorf("assign ipv6 address for %s failed, %v", eniID, err)
	}

	return eniID, nil
}

// attachENI calls EC2 API to attach the ENI and make sure it's status is inuse.
func (e *VolcApiImpl) attachENI(eniID string) (*ec2.DescribeNetworkInterfaceAttributesOutput, error) {
	var err error
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
		_, err = e.ec2Client.AttachNetworkInterface(&vpc.AttachNetworkInterfaceInput{
			InstanceId:         volcengine.String(e.GetInstanceId()),
			NetworkInterfaceId: volcengine.String(eniID),
		})
		errCodes := &apiErr.OpenApiErrCodeChain{}
		if errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus, apiErr.InvalidEniInvalidStatus,
			apiErr.LimitExceededEnisPerInstance).ErrChainEqual(err) {
			return false, err
		}
		return err == nil, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("Attach ENI %s failed: %s", eniID, err.Error())
		return nil, fmt.Errorf("attach ENI %s failed: %s", eniID, err.Error())
	}

	var eniAttributes *ec2.DescribeNetworkInterfaceAttributesOutput
	werr = wait.ExponentialBackoff(backoff.BackOff(backoff.APIStatusWait), func() (bool, error) {
		eniAttributes, err = e.ec2Client.DescribeNetworkInterfaceAttributes(&vpc.DescribeNetworkInterfaceAttributesInput{
			NetworkInterfaceId: volcengine.String(eniID),
		})
		if err == nil && volcengine.StringValue(eniAttributes.Status) == ENIStatusInuse {
			return true, nil
		}
		return false, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		return nil, fmt.Errorf("eni %s status has not become %s: %s", eniID, ENIStatusInuse, err.Error())
	}
	return eniAttributes, nil
}

func (e *VolcApiImpl) AllocENI(subnetId string, securityGroups []string, trunk bool, ipCnt int) (*types.ENI, error) {
	lg := log.WithFields(logger.Fields{
		"SubnetId":       subnetId,
		"InstanceId":     e.GetInstanceId(),
		"SecurityGroups": securityGroups,
		"IPCnt":          ipCnt,
	})
	lg.Infof("Creating eni")

	ipv4Cnt, ipv6Cnt := 0, 0
	if e.ipFamily.EnableIPv4() {
		ipv4Cnt = ipCnt
	}
	if e.ipFamily.EnableIPv6() {
		ipv6Cnt = ipCnt
	}

	eniId, err := e.createENI(subnetId, securityGroups, trunk, ipv4Cnt, ipv6Cnt)
	if err != nil {
		fmtErr := fmt.Sprintf("AllocENI failed, %v", err)
		_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventAllocateResourceFailed, fmtErr)
		return nil, fmt.Errorf("AllocENI: failed to create ENI: %v", err)
	}

	lg = lg.WithFields(logger.Fields{"EniId": eniId})
	eniAttr, err := e.attachENI(eniId)
	if err != nil {
		lg.Errorf("Attach eni failed, deleting")
		delErr := e.deleteENI(eniId)
		if delErr != nil {
			lg.Errorf("Failed to delete newly created ENI %s: %v", eniId, delErr)
		}
		return nil, fmt.Errorf("alloc ENI: error attaching ENI: %s", err.Error())
	}

	defer func() {
		if err != nil {
			rollErr := e.FreeENI(eniId)
			if rollErr != nil {
				fmtErr := fmt.Sprintf("Free eni failed while rollback AllocENI, %v", rollErr)
				_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventAllocateResourceFailed, fmtErr)
				lg.Errorf(fmtErr)
			}
		}
	}()

	var eni *types.ENI
	var inErr error
	err = wait.ExponentialBackoff(backoff.BackOff(backoff.APIStatusWait), func() (bool, error) {
		eni, inErr = e.GetENI(volcengine.StringValue(eniAttr.MacAddress))
		if inErr != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("get eni from metadata failed, %v, %v", inErr, err)
	}
	eni.Trunk = volcengine.StringValue(eniAttr.Type) == ENITypeTrunk
	if e.ipFamily.EnableIPv6() && len(eniAttr.IPv6Sets) > 0 {
		eni.PrimaryIP.IPv6 = net.ParseIP(volcengine.StringValue(eniAttr.IPv6Sets[0]))
	}
	return eni, nil
}

func (e *VolcApiImpl) FreeENI(eniID string) error {
	return e.freeENI(eniID, 2*time.Second)
}

// GetAttachedENIs return all attached eni created by cello
func (e *VolcApiImpl) GetAttachedENIs(withTrunk bool) (result []*types.ENI, err error) {
	enis, err := e.getNetworkInterfacesByDescribe(ENIStatusInuse, "", nil, BuildFilterForDescribeNetworkInterfacesInput(e.tags))
	if err != nil {
		return nil, fmt.Errorf("filter eni by tags failed, %v", err)
	}

	var macs []string
	celloCreatedEni := map[string]*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput{}
	for _, eni := range enis {
		celloCreatedEni[volcengine.StringValue(eni.NetworkInterfaceId)] = eni
		macs = append(macs, volcengine.StringValue(eni.MacAddress))
	}
	log.Infof("Attached eni created by cello(withTrunk: %v): %v", withTrunk, macs)

	for _, mac := range macs {
		eni, inErr := e.GetENI(mac)
		if inErr != nil {
			return nil, inErr
		}
		if item, exist := celloCreatedEni[eni.ID]; exist {
			eni.Trunk = volcengine.StringValue(item.Type) == ENITypeTrunk
			if eni.Trunk && !withTrunk {
				continue
			}
			if e.ipFamily.EnableIPv6() && len(item.IPv6Sets) > 0 {
				eni.PrimaryIP.IPv6 = net.ParseIP(volcengine.StringValue(item.IPv6Sets[0]))
			}
			result = append(result, eni)
		}
	}
	return
}

// GetTotalAttachedEniCnt return count of all eni attached to instance, even across accounts
// contains primary、secondary、trunk
func (e *VolcApiImpl) GetTotalAttachedEniCnt() (int, error) {
	var inErr error
	var output *ecs.DescribeInstancesOutput
	err := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		output, inErr = e.ec2Client.DescribeInstances(&ecs.DescribeInstancesInput{
			VpcId:       volcengine.String(e.GetVpcId()),
			InstanceIds: []*string{volcengine.String(e.GetInstanceId())},
		})
		if inErr != nil {
			return false, nil
		}
		return true, nil
	})
	if err = apiErr.BackoffErrWrapper(err, inErr); err != nil {
		return 0, fmt.Errorf("desribe instance failed, %v, %v", err, inErr)
	}
	if output == nil || len(output.Instances) != 1 {
		return 0, fmt.Errorf("desribe instance failed, no result")
	}
	return len(output.Instances[0].NetworkInterfaces), nil
}

func (e *VolcApiImpl) GetSecondaryENIMACs() ([]string, error) {
	// In some subsequent scenarios, such as rdma and cross-accounts,
	// the full mac obtained from the metadata service also includes non-secondary network interfaces,
	// so openapi can only be used instead.
	var result []string
	enis, err := e.getNetworkInterfacesByDescribe(ENIStatusInuse, ENITypeSecondary, nil, BuildFilterForDescribeNetworkInterfacesInput(e.tags))
	if err != nil {
		return nil, fmt.Errorf("filter eni by tags failed, %v", err)
	}
	for _, eni := range enis {
		result = append(result, volcengine.StringValue(eni.MacAddress))
	}
	return result, nil
}

// GetENIIPList returns the IPs for a given ENI from instance metadata service.
func (e *VolcApiImpl) GetENIIPList(eniMac string) ([]net.IP, []net.IP, error) {
	e.privateIPMutex.RLock()
	defer e.privateIPMutex.RUnlock()
	ctx := context.Background()
	primaryIP, err := e.metadataSvc.GetENIPrimaryIP(ctx, eniMac)
	if err != nil {
		return nil, nil, err
	}
	privateIPv4s, err := e.metadataSvc.GetENIPrivateIPv4s(ctx, eniMac)
	if err != nil {
		return nil, nil, err
	}

	// FIXME open after metadata support ipv6
	//privateIPv6s, err := e.metadataSvc.GetENIPrivateIPv6s(context.Background(), eniMac)
	//if err != nil {
	//	return nil, nil, err
	//}

	eniId, err := e.metadataSvc.GetENIID(ctx, eniMac)
	if err != nil {
		return nil, nil, fmt.Errorf("get eni id failed, %v", err)
	}
	var eniAttributes *ec2.DescribeNetworkInterfaceAttributesOutput
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		eniAttributes, err = e.ec2Client.DescribeNetworkInterfaceAttributes(&vpc.DescribeNetworkInterfaceAttributesInput{
			NetworkInterfaceId: volcengine.String(eniId),
		})
		return err == nil, nil
	})
	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		return nil, nil, err
	}
	privateIPv6s, err := ip2.ParseIPs(volcengine.StringValueSlice(eniAttributes.IPv6Sets))
	if err != nil {
		return nil, nil, err
	}

	return append([]net.IP{primaryIP}, privateIPv4s...), privateIPv6s, nil
}

func (e *VolcApiImpl) AllocIPAddresses(eniID, eniMac string, v4Cnt, v6Cnt int) ([]net.IP, []net.IP, error) {
	if eniID == "" || eniMac == "" {
		return nil, nil, fmt.Errorf("args incorrect")
	}
	e.privateIPMutex.Lock()
	defer e.privateIPMutex.Unlock()

	var err, v4Err, v6Err error
	var wg sync.WaitGroup
	var ipv4s, ipv6s []net.IP
	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("AllocIPAddresses failed, %v", err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventAllocateResourceFailed, fmtErr)
			log.Warnf("Rollback AllocIPAddresses due to %s", fmtErr)
			// rollback
			err = e.deallocIPAddressesWithLocked(eniID, eniMac, ipv4s, ipv6s)
			if err != nil {
				fmtErr = fmt.Sprintf("DeallocIPAddress failed while rollback AllocIPAddresses, %v", err)
				_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventAllocateResourceFailed, fmtErr)
				log.Errorf(fmtErr)
			}
		}
	}()

	if e.ipFamily.EnableIPv4() && v4Cnt > 0 {
		var assignIPResp *vpc.AssignPrivateIpAddressesOutput
		werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
			assignIPResp, err = e.ec2Client.AssignPrivateIpAddress(&vpc.AssignPrivateIpAddressesInput{
				NetworkInterfaceId:             volcengine.String(eniID),
				SecondaryPrivateIpAddressCount: volcengine.Int64(int64(v4Cnt)),
			})
			if err == nil {
				return true, nil
			}
			errCodes := &apiErr.OpenApiErrCodeChain{}
			if errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus, apiErr.InvalidEniInvalidStatus, apiErr.InsufficientIpInSubnet,
				apiErr.LimitExceededPrivateIpsPerEni, apiErr.QuotaExceededSecurityGroupIp).ErrChainEqual(err) {
				return false, err
			}
			return false, nil
		})
		if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
			return ipv4s, ipv6s, fmt.Errorf("failed to assign private ips on ENI %s, err: %s", eniID, err.Error())
		}

		ipl := len(assignIPResp.PrivateIpSet)
		if ipl < v4Cnt {
			return ipv4s, ipv6s, fmt.Errorf("the total number of ips is %d, less than wanted: %d", ipl, v4Cnt)
		}
		ipv4s, err = ip2.ParseIPs(volcengine.StringValueSlice(assignIPResp.PrivateIpSet[ipl-v4Cnt:]))
		if err != nil {
			return ipv4s, ipv6s, err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			var inErr error
			var metaV4s []net.IP
			v4Err = wait.ExponentialBackoff(backoff.BackOff(backoff.MetaStatusWait), func() (bool, error) {
				metaV4s, inErr = e.metadataSvc.GetENIPrivateIPv4s(context.Background(), eniMac)
				if inErr != nil {
					return false, nil
				}
				if !ip2.NetIPContainAll(metaV4s, ipv4s) {
					return false, nil
				}
				return true, nil
			})
			if v4Err != nil {
				v4Err = fmt.Errorf("%w, metadata err: %v", v4Err, inErr)
			}
		}()
	}

	if e.ipFamily.EnableIPv6() && v6Cnt > 0 {
		var assignIPResp *ec2.AssignIpv6AddressesOutput
		werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
			assignIPResp, err = e.ec2Client.AssignIpv6Addresses(&ec2.AssignIpv6AddressesInput{
				NetworkInterfaceId: volcengine.String(eniID),
				Ipv6AddressCount:   volcengine.Int64(int64(v6Cnt)),
			})
			if err == nil {
				return true, nil
			}
			errCodes := &apiErr.OpenApiErrCodeChain{}
			if errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus, apiErr.InvalidEniInvalidStatus, apiErr.InsufficientIpInSubnet,
				apiErr.LimitExceededIpv6AddressesPerEni, apiErr.InvalidSubnetDisableIpv6, apiErr.QuotaExceededSecurityGroupIp).ErrChainEqual(err) {
				return false, err
			}
			return false, nil
		})
		if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
			return ipv4s, ipv6s, fmt.Errorf("failed to assign ipv6 address on ENI %s, err: %v", eniID, err)
		}
		ipl := len(assignIPResp.Ipv6Set)
		if ipl < v6Cnt {
			return ipv4s, ipv6s, fmt.Errorf("the total number of ips is %d, less than wanted: %d", ipl, v6Cnt)
		}
		ipv6s, err = ip2.ParseIPs(volcengine.StringValueSlice(assignIPResp.Ipv6Set[ipl-v6Cnt:]))
		if err != nil {
			return ipv4s, ipv6s, err
		}

		// TODO: after metadata support ipv6
		//wg.Add(1)
		//go func() {
		//	defer wg.Done()
		//	var inErr error
		//	var metaV6s []net.IP
		//	v6Err = wait.ExponentialBackoff(backoff.BackOff(backoff.MetaStatusWait), func() (bool, error) {
		//		metaV6s, inErr = e.metadataSvc.GetENIPrivateIPv6s(context.Background(), eniMac)
		//		if inErr != nil {
		//			return false, nil
		//		}
		//		if !utils.NetIPContainAll(metaV6s, ipv6s) {
		//			return false, nil
		//		}
		//		return true, nil
		//	})
		//	if v6Err != nil {
		//		v6Err = fmt.Errorf("%w, metadata err: %v", v6Err, inErr)
		//	}
		//}()
	}
	wg.Wait()

	err = k8sErr.NewAggregate([]error{v4Err, v6Err})
	if err != nil {
		return nil, nil, err
	}
	log.Infof("Successfully assigned IP address on ENI %s, ipv4s: %s, ipv6s: %s", eniID, ip2.ToStringSlice(ipv4s), ip2.ToStringSlice(ipv6s))
	return ipv4s, ipv6s, nil
}

func (e *VolcApiImpl) DeallocIPAddresses(eniID, eniMac string, ipv4s, ipv6s []net.IP) error {
	e.privateIPMutex.Lock()
	defer e.privateIPMutex.Unlock()

	err := e.deallocIPAddressesWithLocked(eniID, eniMac, ipv4s, ipv6s)
	return err
}

func (e *VolcApiImpl) deallocIPAddressesWithLocked(eniID, eniMac string, ipv4s, ipv6s []net.IP) (err error) {
	if eniID == "" || eniMac == "" {
		return fmt.Errorf("args incorrect")
	}
	if len(ipv4s) == 0 && len(ipv6s) == 0 {
		return nil
	}

	var errs []error
	lg := log.WithFields(logger.Fields{
		"ENI":   eniID,
		"IPv4s": ip2.ToStringSlice(ipv4s),
		"IPv6s": ip2.ToStringSlice(ipv6s),
	})
	lg.Infof("Deallocating ipaddress")

	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("DeallocIPAddresses for eni %s failed, %v", eniID, err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventReleaseResourceFailed, fmtErr)
		} else {
			lg.Infof("UnAssigned ipaddress")
		}
	}()

	part := 0
	if len(ipv4s) > 0 {
		part++
		werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
			_, err = e.ec2Client.UnAssignPrivateIpAddress(&vpc.UnassignPrivateIpAddressesInput{
				NetworkInterfaceId: volcengine.String(eniID),
				PrivateIpAddress:   volcengine.StringSlice(ip2.ToStringSlice(ipv4s)),
			})
			if err == nil {
				return true, nil
			}
			errCodes := &apiErr.OpenApiErrCodeChain{}
			if errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus, apiErr.InvalidEniInvalidStatus).ErrChainEqual(err) {
				return false, err
			}
			errCodes = &apiErr.OpenApiErrCodeChain{}
			if errCodes.WithErrCodes(apiErr.InvalidPrivateIpMalformed, apiErr.InvalidEniIdNotFound).ErrChainEqual(err) {
				return true, nil
			}
			lg.Warnf("UnAssignPrivateIpAddress failed: %s", err.Error())
			return false, nil
		})

		if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
			errs = append(errs, err)
		}
	}

	if len(ipv6s) > 0 {
		part++
		werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
			_, err = e.ec2Client.UnassignIpv6Addresses(&ec2.UnassignIpv6AddressesInput{
				NetworkInterfaceId: volcengine.String(eniID),
				Ipv6Address:        volcengine.StringSlice(ip2.ToStringSlice(ipv6s)),
			})
			if err == nil {
				return true, nil
			}
			errCodes := &apiErr.OpenApiErrCodeChain{}
			if errCodes.WithPublicErrCodes().WithErrCodes(apiErr.InvalidVpcInvalidStatus, apiErr.InvalidEniInvalidStatus).ErrChainEqual(err) {
				return false, err
			}
			errCodes = &apiErr.OpenApiErrCodeChain{}
			if errCodes.WithErrCodes(apiErr.InvalidIpv6Malformed, apiErr.InvalidEniIdNotFound).ErrChainEqual(err) {
				return true, nil
			}
			lg.Warnf("UnassignIpv6Addresses failed: %v", err)
			return false, nil
		})

		if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		if len(errs) != part {
			errs = append(errs, apiErr.ErrHalfwayFailed)
		}
		return k8sErr.NewAggregate(errs)
	}

	var inErr error
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.MetaStatusWait), func() (bool, error) {
		var metaV4s []net.IP
		metaV4s, inErr = e.metadataSvc.GetENIPrivateIPv4s(context.Background(), eniMac)
		if inErr != nil {
			return false, nil
		}

		//metaV6s, inErr = e.metadataSvc.GetENIPrivateIPv6s(context.Background(), eniMac)
		//if inErr != nil {
		//	return false, nil
		//}

		if len(ipv4s) > 0 && ip2.NetIPContainAny(metaV4s, ipv4s) {
			inErr = fmt.Errorf("ips %s expecte to be unassign, but currently has %s", ipv4s, metaV4s)
			return false, nil
		}
		//if len(ipv6s) > 0 && ip2.NetIPContainAny(metaV6s, ipv6s) {
		//	inErr = fmt.Errorf("ips %s expecte to be unassign, but currently has %s", ipv6s, metaV6s)
		//	return false, nil
		//}
		return true, nil
	})

	if werr != nil {
		return inErr
	}
	return nil
}

// GetInstanceLimit return IP address limit per ENI.
func (e *VolcApiImpl) GetInstanceLimit() (*InstanceLimits, error) {
	var resp *ec2.DescribeInstanceTypesOutput
	var err error
	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("get ip/eni quota for instance failed, %v", err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventGetInstanceQuotaFailed, fmtErr)
		}
	}()
	log.Info("Waiting to get the maximum number of ip on an eni")
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		resp, err = e.ec2Client.DescribeInstanceTypes(&ecs.DescribeInstanceTypesInput{
			InstanceTypes: volcengine.StringSlice([]string{e.GetInstanceType()}),
		})
		if err != nil {
			log.Warnf("DescribeInstanceType %s failed, %v [requestId: %s]",
				e.GetInstanceType(), err, resp.Metadata.RequestId)
			return false, nil
		}
		if len(resp.InstanceTypes) != 1 ||
			volcengine.StringValue(resp.InstanceTypes[0].InstanceTypeId) != e.GetInstanceType() {
			return false, fmt.Errorf("DescribeInstanceType %s failed, no result [requestId: %s]",
				e.GetInstanceType(), resp.Metadata.RequestId)
		}
		return true, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("Get instance limits failed: %s", err.Error())
		return nil, err
	}
	instance := resp.InstanceTypes[0]

	limit := &InstanceLimits{
		InstanceLimitsAttr: InstanceLimitsAttr{
			ENITotal:       int(volcengine.Int32Value(instance.NetworkInterfaceTotalNumQuota)),
			ENIQuota:       int(volcengine.Int32Value(instance.Network.MaximumNetworkInterfaces)),
			IPv4MaxPerENI:  int(volcengine.Int32Value(instance.Network.MaximumPrivateIpv4AddressesPerNetworkInterface)),
			IPv6MaxPerENI:  int(volcengine.Int32Value(instance.Network.MaximumPrivateIpv4AddressesPerNetworkInterface)),
			TrunkSupported: volcengine.BoolValue(instance.TrunkNetworkInterfaceSupported),
		},
	}

	// TODO assert ENITotal which now is 0
	if limit.NonPrimaryENI() <= 0 {
		return nil, fmt.Errorf("limits of instance %s invalid, %s", e.GetInstanceId(), limit.String())
	}
	log.WithFields(logger.Fields{"InstanceID": e.GetInstanceId(), "RequestID": resp.Metadata.RequestId}).
		Infof("Limits: %s", limit.String())
	return limit, nil
}

// cleanUpLeakedENIs clean up the leaked ENIs period.
func (e *VolcApiImpl) cleanUpLeakedENIs() {
	rand.Seed(time.Now().UnixNano())
	back := time.Duration(rand.Intn(300)) * time.Second
	time.Sleep(back)

	log.Debug("Checking for leaked ENIs.")
	leakedENIs, err := e.getLeakedENIs()

	if err != nil {
		log.Errorf("Unable to get leaked ENI: %v", err)
		return
	}
	for _, eni := range leakedENIs {
		err := e.deleteENI(eni)
		if err != nil {
			log.Warnf("Failed to clean up leaked ENI %s: %v", eni, err)
		} else {
			log.Infof("Cleaned up leaked ENI %s", eni)
		}
	}
}

func (e *VolcApiImpl) describeNetworkInterfacesWithPage(pageNumber int, status string, eniType string, eniIDs []string, inputFilter []*vpc.TagFilterForDescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error) {
	var resp *ec2.DescribeNetworkInterfacesOutput
	var err error
	input := &vpc.DescribeNetworkInterfacesInput{
		Type:                volcengine.String(eniType),
		VpcId:               volcengine.String(e.GetVpcId()),
		NetworkInterfaceIds: volcengine.StringSlice(eniIDs),
		PageNumber:          volcengine.Int64(int64(pageNumber)),
		PageSize:            volcengine.Int64(maxPageSize),
	}
	if status != "" {
		input.Status = volcengine.String(status)
	}
	if status == ENIStatusInuse {
		input.InstanceId = volcengine.String(e.GetInstanceId())
	}

	if inputFilter != nil {
		input.TagFilters = inputFilter
	}

	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		resp, err = e.ec2Client.DescribeNetworkInterfaces(input)
		return err == nil, nil
	})
	return resp, apiErr.BackoffErrWrapper(werr, err)
}

// getNetworkInterfacesByDescribe get eni list filter with inputFilter by openapi DescribeNetworkInterfaces.
func (e *VolcApiImpl) getNetworkInterfacesByDescribe(status string, eniType string, eniIDs []string, inputFilter []*vpc.TagFilterForDescribeNetworkInterfacesInput) ([]*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	var result []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput
	pages := 1
	first := true
	for i := 1; i <= pages; i++ {
		resp, err := e.describeNetworkInterfacesWithPage(i, status, eniType, eniIDs, inputFilter)
		if err != nil {
			log.Errorf("describeNetworkInterfacesWithPage failed: %s", err.Error())
			return result, err
		}
		total := int(volcengine.Int64Value(resp.TotalCount))
		if total == 0 {
			return result, nil
		}
		result = append(result, resp.NetworkInterfaceSets...)
		if first {
			pages = total / maxPageSize
			if total%maxPageSize != 0 {
				pages += 1
			}
			first = false
			log.Debugf("Pages: %d", pages)
		}
	}
	return result, nil
}

// getUnAttachedENIs get all ENI that created by cello but not attached.
func (e *VolcApiImpl) getUnAttachedENIs() ([]*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	return e.getNetworkInterfacesByDescribe(ENIStatusAvailable, ENITypeSecondary, nil, BuildFilterForDescribeNetworkInterfacesInput(e.tags))
}

func (e *VolcApiImpl) getLeakedENIs() ([]string, error) {
	enis, err := e.getUnAttachedENIs()
	if err != nil {
		return nil, fmt.Errorf("get unAattached ENIs failed: %s", err.Error())
	}

	var leaked []string
	for _, eni := range enis {
		updateTime, err := time.Parse(time.RFC3339, volcengine.StringValue(eni.UpdatedAt))
		if err != nil {
			log.Errorf("parse eni create time error: %s", err.Error())
			continue
		}
		if time.Since(updateTime) > eniLeakedTime {
			leaked = append(leaked, volcengine.StringValue(eni.NetworkInterfaceId))
		}
	}
	return leaked, nil
}

// GetENI get types.ENI by mac from metadata.
func (e *VolcApiImpl) GetENI(mac string) (*types.ENI, error) {
	ctx := context.Background()
	eniMac, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("get eni mac failed: %s", err.Error())
	}

	v4Gateway, err := e.metadataSvc.GetENIIPv4Gateway(ctx, mac)
	if err != nil {
		return nil, fmt.Errorf("faild to get gateway for eni mac [%s]: %s", mac, err.Error())
	}

	eniID, err := e.metadataSvc.GetENIID(ctx, mac)
	if err != nil {
		return nil, fmt.Errorf("get eni id failed: %s", err.Error())
	}

	subnetID, err := e.metadataSvc.GetENISubnetID(ctx, mac)
	if err != nil {
		return nil, fmt.Errorf("get subnet id failed: %s", err.Error())
	}

	primaryIP, err := e.metadataSvc.GetENIPrimaryIP(ctx, mac)
	if err != nil {
		log.Errorf("Get primary ip failed: %s", err.Error())
		return nil, fmt.Errorf("get primary ip failed: %s", err.Error())
	}

	//TODO: should be removed when metadata support ipv6.
	subnet := e.subnetMgr.GetPodSubnet(subnetID)
	if subnet == nil {
		return nil, fmt.Errorf("cant find subent %s", subnetID)
	}
	var v4Cidr, v6Cidr *net.IPNet
	var v6Gateway net.IP
	if subnet.IPFamily().EnableIPv4() {
		_, v4Cidr, err = net.ParseCIDR(subnet.IPv4Cidr)
		if err != nil {
			return nil, fmt.Errorf("parse v4Cidr failed, %v", err)
		}
	}

	if subnet.IPFamily().EnableIPv6() {
		_, v6Cidr, err = net.ParseCIDR(subnet.IPv6Cidr)
		if err != nil {
			return nil, fmt.Errorf("parse v6Cidr failed, %v", err)
		}
		v6Gateway = ip.NextIP(v6Cidr.IP)
	}

	eni := &types.ENI{
		ID:  eniID,
		Mac: eniMac,
		PrimaryIP: types.IPSet{
			IPv4: primaryIP,
		},
		Subnet: types.Subnet{
			ID: subnetID,
			Gateway: &types.IPSet{
				IPv4: v4Gateway,
				IPv6: v6Gateway,
			},
			GatewayMac: nil, //TODO
			CIDR: &types.IPNetSet{
				IPv4: v4Cidr,
				IPv6: v6Cidr,
			},
		},
	}
	return eni, nil
}

func New(apiClient ec2.EC2, ipStack types.IPFamily, subnetMgr SubnetManager, instanceMetadata InstanceMetadataGetter,
	platform string) (*VolcApiImpl, error) {
	tags := make(map[string]string)
	if platform == "" || strings.EqualFold(platform, config.PlatformVKE) {
		tags[VkePlatformTagKey] = VkePlatformTagValue
		tags[VkeComponentTagKey] = Component
		tags[VkeInstanceIdTagKey] = instanceMetadata.GetInstanceId()
	} else {
		tags[K8sComponentTagKey] = Component
		tags[K8sInstanceIdTagKey] = instanceMetadata.GetInstanceId()
	}

	impl := &VolcApiImpl{
		ipFamily:               ipStack,
		metadataSvc:            metadata.NewEC2MetadataWrapper(metadata.New()),
		ec2Client:              apiClient,
		InstanceMetadataGetter: instanceMetadata,
		subnetMgr:              subnetMgr,
		tags:                   tags,
	}

	go wait.Forever(impl.cleanUpLeakedENIs, time.Hour)

	log.Infof("VolcApiImpl created")
	return impl, nil
}
