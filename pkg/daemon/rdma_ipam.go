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

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/utils/runtime"
	"net"
	"path"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/vishvananda/netlink"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/backoff"
	"github.com/volcengine/cello/pkg/plugins/ipam/cidr"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/types"
)

type RdmaIpamManager struct {
	ipams          *cidr.AllocatorGroup
	rdmaInterfaces map[string]types.RdmaInterface
}

func (d *daemon) initRdmaIpam() error {
	anno, err := d.k8s.GetNodeAnnotation()
	if err != nil {
		return err
	}
	info := make([]types.RdmaInterface, 0)
	if infoStr, exist := anno[types.AnnotationRdmaInfo]; exist {
		err = json.Unmarshal([]byte(infoStr), &info)
		if err != nil {
			return err
		}
	}

	linkHasAddresses := func(link netlink.Link, ips []net.IPNet, matchPrefix bool) ([]net.IPNet, error) {
		var matches []net.IPNet
		addresses, inErr := iproute.GetLinkAddresses(link)
		if inErr != nil {
			return nil, fmt.Errorf("get address for device %s failed, %v", link.Attrs().HardwareAddr, inErr)
		}
		addrMap := map[string]net.IPNet{}
		ipMap := map[string]net.IPNet{}
		for _, addr := range addresses {
			ipMap[addr.IP.String()] = *addr.IPNet
			addrMap[addr.IPNet.String()] = *addr.IPNet
		}

		matchMap := ipMap
		if matchPrefix {
			matchMap = addrMap
		}

		for _, ipAddr := range ips {
			k := ipAddr.IP.String()
			if matchPrefix {
				k = ipAddr.String()
			}
			if m, exist := matchMap[k]; exist {
				matches = append(matches, m)
			}
		}
		return matches, nil
	}

	//// check info
	//if len(info) > 0 {
	//	for _, rdma := range info {
	//		link, inErr := iproute.LinkByMac(rdma.Mac.String())
	//		if inErr != nil {
	//			return fmt.Errorf("get device %s failed, %v", rdma.Mac, inErr)
	//		}
	//		if link.Attrs().OperState != netlink.OperUp {
	//			return fmt.Errorf("device %s not up", rdma.Mac)
	//		}
	//		matches, inErr := linkHasAddresses(link, rdma.Cidrs, true)
	//		if inErr != nil {
	//			return inErr
	//		}
	//		if len(matches) == len(rdma.Cidrs) {
	//			return fmt.Errorf("adresses of device %s no match cidrs %s", rdma.Mac, rdma.Cidrs)
	//		}
	//	}
	//}

	if len(info) == 0 && datatype.BoolValue(d.cfg.ProbeRdma) {
		// find rdma
		var output *ecs.DescribeInstancesOutput
		var inErr error
		err = wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
			output, inErr = d.ecsMetaGetter.DescribeInstances(&ecs.DescribeInstancesInput{
				VpcId:       volcengine.String(d.instanceMeta.GetVpcId()),
				InstanceIds: []*string{volcengine.String(d.instanceMeta.GetInstanceId())},
			})
			return inErr == nil, nil
		})
		if err = apiErr.BackoffErrWrapper(err, inErr); err != nil {
			return fmt.Errorf("get rdma info failed, %v", err)
		}
		rdmaIpAddresses := volcengine.StringValueSlice(output.Instances[0].RdmaIpAddresses)
		if len(rdmaIpAddresses) == 0 {
			return nil
		}

		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, rdmaIPStr := range rdmaIpAddresses {
			rdmaIP := net.ParseIP(rdmaIPStr)
			for _, link := range links {
				switch link.(type) {
				case *netlink.Device:
					matches, err2 := linkHasAddresses(link, []net.IPNet{{
						IP:   rdmaIP,
						Mask: net.CIDRMask(32, 32),
					}}, false)
					if err2 != nil {
						return fmt.Errorf("find %s on %s failed, %v", rdmaIPStr, link.Attrs().HardwareAddr, err2)
					}
					if len(matches) == 1 {
						info = append(info, types.RdmaInterface{
							IfName: link.Attrs().Name,
							Mac:    link.Attrs().HardwareAddr.String(),
							Cidr:   matches[0].String(),
						})
					}
				default:
					continue
				}
			}
		}
		if len(rdmaIpAddresses) != len(info) {
			return fmt.Errorf("not found all rdma interfaces, rdma from remote: %v, from local: %v", rdmaIpAddresses, info)
		}

		b, inErr := json.Marshal(info)
		if inErr != nil {
			return inErr
		}

		// patch info
		annoPatch := map[string]interface{}{
			types.AnnotationRdmaInfo: string(b),
		}
		inErr = d.k8s.PatchNodeAnnotation(annoPatch)
		if inErr != nil {
			return fmt.Errorf("annotate rdma info to node failed, %v", inErr)
		}
	}

	if len(info) == 0 {
		log.Infof("Skip rdma ipam init due to no rdma info")
		return nil
	}

	// init
	ipamCfg := &cidr.Config{
		DataDir: datatype.StringValue(d.cfg.RdmaIpamDataDir),
		Ranges:  map[string]*allocator.RangeSet{},
	}

	rdmaInterfaces := map[string]types.RdmaInterface{}
	for _, i := range info {
		rdmaInterfaces[i.Mac] = i
		ipAddr, subnet, inErr := net.ParseCIDR(i.Cidr)
		if inErr != nil {
			return fmt.Errorf("parse subnet %s failed, %v", i.Cidr, inErr)
		}
		ipamCfg.Ranges[i.Mac] = &allocator.RangeSet{allocator.Range{
			RangeStart: ip.NextIP(ipAddr),
			RangeEnd:   nil,
			Subnet:     cniTypes.IPNet(*subnet),
			Gateway:    nil,
		}}
	}

	err = cidr.PrepareConfig(ipamCfg)
	if err != nil {
		return fmt.Errorf("rdma ipam config err, %v", err)
	}
	ipam, err := cidr.NewAllocatorGroup(ipamCfg)
	if err != nil {
		return fmt.Errorf("init rdma ipam failed, %v", err)
	}
	d.rdmaIpamManager = &RdmaIpamManager{
		ipams:          ipam,
		rdmaInterfaces: rdmaInterfaces,
	}
	return nil
}

func (d *daemon) createRdmaEndpoint(_ context.Context, req *pbrpc.CreateEndpointRequest) (resp *pbrpc.CreateEndpointResponse, err error) {
	lg := log.WithFields(logger.Fields{
		"Namespace":          req.Namespace,
		"Name":               req.Name,
		"SandboxContainerId": req.InfraContainerId,
		"IfName":             req.IfName,
		"IpamType":           req.IpamType,
		"IpamArgs":           req.IpamArgs.String(),
	})
	lg.Infof("Handle createRdmaEndpoint")

	defer runtime.HandleCrash(lg)
	defer func() {
		if err != nil {
			lg.Warnf("Fail to handle createRdmaEndpoint: %v", err)
		} else {
			lg.Infof("CreateRdmaEndpoint result: %s", resp.String())
		}
	}()

	if d.rdmaIpamManager == nil {
		return nil, fmt.Errorf("rdma ipam not init")
	}

	var netWorkInterface *pbrpc.NetworkInterface
	if req.GetIpamType() == types.IPAMTypeRdmaExclusive {
		c := d.rdmaIpamManager.rdmaInterfaces[req.GetIpamArgs().GetDeviceId()]
		address, ipNet, _ := net.ParseCIDR(c.Cidr)
		ipAddr := &net.IPNet{
			IP:   address,
			Mask: ipNet.Mask,
		}
		netWorkInterface = &pbrpc.NetworkInterface{
			ENI: &pbrpc.ENI{
				Mac:         req.GetIpamArgs().GetDeviceId(),
				IPv4Gateway: ip.NextIP(ipNet.IP).String(),
			},
			IPv4Addr:     ipAddr.String(),
			IfName:       req.IfName,
			DefaultRoute: false,
		}
	} else {
		ipCfg, err := d.rdmaIpamManager.ipams.Get(req.GetIpamArgs().GetDeviceId(), ownerId(req.Namespace, req.Name), req.IfName, nil)
		if err != nil {
			return nil, err
		}

		netWorkInterface = &pbrpc.NetworkInterface{
			ENI: &pbrpc.ENI{
				Mac:         req.GetIpamArgs().GetDeviceId(),
				IPv4Gateway: ipCfg.Gateway.String(),
			},
			IPv4Addr:     ipCfg.Address.String(),
			IfName:       req.IfName,
			DefaultRoute: false,
		}
	}

	return &pbrpc.CreateEndpointResponse{Interfaces: []*pbrpc.NetworkInterface{netWorkInterface}}, nil
}

func (d *daemon) deleteRdmaEndpoint(_ context.Context, req *pbrpc.DeleteEndpointRequest) (resp *pbrpc.DeleteEndpointResponse, err error) {
	lg := log.WithFields(logger.Fields{
		"Namespace":          req.Namespace,
		"Name":               req.Name,
		"SandboxContainerId": req.InfraContainerId,
		"IfName":             req.IfName,
		"IpamType":           req.IpamType,
		"IpamArgs":           req.IpamArgs.String(),
	})
	lg.Infof("Handle deleteRdmaEndpoint")

	defer runtime.HandleCrash(lg)
	defer func() {
		if err != nil {
			lg.Warnf("Fail to handle deleteRdmaEndpoint: %v", err)
		} else {
			lg.Infof("Handle deleteRdmaEndpoint succeed")
		}
	}()

	if req.GetIpamType() == types.IPAMTypeRdmaExclusive {
		return &pbrpc.DeleteEndpointResponse{}, nil
	}

	// NOTICE: not support stateful pod
	if d.rdmaIpamManager == nil {
		return nil, fmt.Errorf("rdma ipam not init")
	}
	err = d.rdmaIpamManager.ipams.Release(req.GetIpamArgs().GetDeviceId(), ownerId(req.Namespace, req.Name), req.IfName)
	if err != nil {
		return nil, err
	}
	return &pbrpc.DeleteEndpointResponse{}, nil
}

func ownerId(ele ...string) string {
	return path.Join(ele...)
}
