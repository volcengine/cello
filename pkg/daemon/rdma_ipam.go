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
	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/plugins/ipam/cidr"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/device"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/utils/runtime"
	"github.com/volcengine/cello/types"
)

type RdmaIpamManager struct {
	ipams          *cidr.AllocatorGroup
	hpcRoute       types.HpcRoute
	rdmaInterfaces map[string]types.RdmaInterface // deviceId -- rdma
}

func (d *daemon) getRdmaInfo() (*types.RdmaInfo, error) {
	info := types.RdmaInfo{}
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

	// find rdma
	rdmaInterfaces, err := device.ListRdma()
	if err != nil {
		return nil, fmt.Errorf("list rdma failed, %v", err)
	}
	log.Info("Found rdma interfaces: %v", rdmaInterfaces)

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
		return nil, fmt.Errorf("get rdma info failed, %v", err)
	}
	rdmaIpAddresses := volcengine.StringValueSlice(output.Instances[0].RdmaIpAddresses)
	if len(rdmaIpAddresses) == 0 {
		return &info, nil
	}
	if len(rdmaInterfaces) != len(rdmaIpAddresses) {
		return nil, fmt.Errorf("number of rdma get from local is %d, not equal to %d get from remote",
			len(rdmaInterfaces), len(rdmaIpAddresses))
	}

	for _, r := range rdmaInterfaces {
		link, mErr := netlink.LinkByName(r.NetName)
		if mErr != nil {
			return nil, mErr
		}
		for _, rdmaIPStr := range rdmaIpAddresses {
			rdmaIP := net.ParseIP(rdmaIPStr)
			matches, err2 := linkHasAddresses(link, []net.IPNet{{
				IP:   rdmaIP,
				Mask: net.CIDRMask(32, 32),
			}}, false)
			if err2 != nil {
				return nil, fmt.Errorf("find %s on %s failed, %v", rdmaIPStr, link.Attrs().HardwareAddr, err2)
			}
			if len(matches) == 1 {
				log.Infof("Found %v match %s on %s", matches, rdmaIPStr, r.NetName)
				info.RdmaInterfaces = append(info.RdmaInterfaces, types.RdmaInterface{
					IfName:   link.Attrs().Name,
					Mac:      link.Attrs().HardwareAddr.String(),
					DeviceId: r.PciAddr,
					Cidr:     matches[0].String(),
				})
			}
		}
	}

	if len(rdmaIpAddresses) != len(info.RdmaInterfaces) {
		return nil, fmt.Errorf("not found all rdma interfaces, rdma from remote: %v, from local: %v", rdmaIpAddresses, info.RdmaInterfaces)
	}
	hpcRoute, err := getHpcRoute(info.RdmaInterfaces)
	if err != nil {
		return nil, fmt.Errorf("get hpc route failed, %v", err)
	}
	info.HpcRoute = *hpcRoute

	return &info, nil
}

func (d *daemon) initRdmaIpamManager() error {
	var rdmaInfo *types.RdmaInfo

	if datatype.BoolValue(config.Config.ProbeRdma) {
		info, err := d.getRdmaInfo()
		if err != nil {
			log.Warnf("Get rdma info failed, %v, try get from node annotation", err)
		} else {
			rdmaInfo = info
		}
	}

	if rdmaInfo == nil || len(rdmaInfo.RdmaInterfaces) == 0 {
		log.Warnf("Unable to get RDMA information, try get from node annotation")
		anno, inErr := d.k8s.GetNodeAnnotation()
		if inErr != nil {
			return inErr
		}
		oldInfo := types.RdmaInfo{}
		if infoStr, exist := anno[types.AnnotationRdmaInfo]; exist {
			err := json.Unmarshal([]byte(infoStr), &oldInfo)
			if err != nil {
				return err
			}
		}
		rdmaInfo = &oldInfo
	} else {
		// patch info
		b, inErr := json.Marshal(*rdmaInfo)
		if inErr != nil {
			return fmt.Errorf("marshal rdma info failed, %v", inErr)
		}
		annoPatch := map[string]interface{}{
			types.AnnotationRdmaInfo: string(b),
		}
		inErr = d.k8s.PatchNodeAnnotation(annoPatch)
		if inErr != nil {
			return fmt.Errorf("annotate rdma info to node failed, %v", inErr)
		}
	}

	if len(rdmaInfo.RdmaInterfaces) == 0 {
		log.Infof("Skip rdma ipam init due to no rdma info")
		return nil
	}

	// init
	ipamCfg := &cidr.Config{
		DataDir: datatype.StringValue(config.Config.RdmaIpamDataDir),
		Ranges:  map[string]*allocator.RangeSet{},
	}

	rdmaInterfaces := map[string]types.RdmaInterface{}
	for _, i := range rdmaInfo.RdmaInterfaces {
		rdmaInterfaces[i.DeviceId] = i
		ipAddr, subnet, inErr := net.ParseCIDR(i.Cidr)
		if inErr != nil {
			return fmt.Errorf("parse subnet %s failed, %v", i.Cidr, inErr)
		}
		if o, b := subnet.Mask.Size(); b == 32 && o > 30 {
			log.Warnf("Network %s of [%s/%s] too small to allocate from, skip", subnet.String(), i.IfName, i.DeviceId)
			continue
		}
		ipamCfg.Ranges[i.DeviceId] = &allocator.RangeSet{allocator.Range{
			RangeStart: ip.NextIP(ipAddr),
			RangeEnd:   nil,
			Subnet:     cniTypes.IPNet(*subnet),
			Gateway:    nil,
		}}
	}

	err := cidr.PrepareConfig(ipamCfg)
	if err != nil {
		return fmt.Errorf("rdma ipam config err, %v", err)
	}
	ipam, err := cidr.NewAllocatorGroup(ipamCfg)
	if err != nil {
		return fmt.Errorf("init rdma ipam failed, %v", err)
	}
	d.rdmaIpamManager = &RdmaIpamManager{
		ipams:          ipam,
		hpcRoute:       rdmaInfo.HpcRoute,
		rdmaInterfaces: rdmaInterfaces,
	}
	log.Infof("Init rdma ipam manager success")
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
	deviceId := req.GetIpamArgs().GetDeviceId()
	rdmaDevice, exist := d.rdmaIpamManager.rdmaInterfaces[deviceId]
	if !exist {
		return nil, fmt.Errorf("not found rdma device by deviceId %s", deviceId)
	}
	if req.GetIpamType() == types.IPAMTypeRdmaExclusive {
		address, ipNet, _ := net.ParseCIDR(rdmaDevice.Cidr)
		ipAddr := &net.IPNet{
			IP:   address,
			Mask: ipNet.Mask,
		}
		netWorkInterface = &pbrpc.NetworkInterface{
			ENI: &pbrpc.ENI{
				Mac:         rdmaDevice.Mac,
				IPv4Gateway: ip.NextIP(ipNet.IP).String(),
			},
			IPv4Addr:     ipAddr.String(),
			IfName:       req.IfName,
			DefaultRoute: false,
		}
	} else {
		ipCfg, err := d.rdmaIpamManager.ipams.Get(deviceId, ownerId(req.Namespace, req.Name), req.IfName, nil)
		if err != nil {
			return nil, err
		}

		netWorkInterface = &pbrpc.NetworkInterface{
			ENI: &pbrpc.ENI{
				Mac:         rdmaDevice.Mac,
				IPv4Gateway: ipCfg.Gateway.String(),
			},
			IPv4Addr:     ipCfg.Address.String(),
			IfName:       req.IfName,
			DefaultRoute: false,
		}
	}
	netWorkInterface.ExtraRoutes = []*pbrpc.Route{{Dst: d.rdmaIpamManager.hpcRoute.Dst}}
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

func getHpcRoute(rdmaInterfaces []types.RdmaInterface) (*types.HpcRoute, error) {
	// NOTICE: not support ipv6, and expected one
	var expectedRoutes []struct {
		dev   string
		route netlink.Route
	}
	for _, rdma := range rdmaInterfaces {
		rdmaLink, err := netlink.LinkByName(rdma.IfName)
		if err != nil {
			log.Warnf("Get rdma link %s failed, %v", rdma.IfName, err)
			continue
		}
		routes, err := netlink.RouteList(rdmaLink, netlink.FAMILY_V4)
		if err != nil {
			log.Warnf("Get routes of rdma link %s failed, %v", rdma.IfName, err)
			continue
		}
		for _, r := range routes {
			if r.Gw != nil && r.Src == nil {
				expectedRoutes = append(expectedRoutes, struct {
					dev   string
					route netlink.Route
				}{dev: rdma.IfName, route: r})
			}
		}
	}
	if l := len(expectedRoutes); l != 1 {
		return nil, fmt.Errorf("num of hpc route is %d, not expected", l)
	}

	return &types.HpcRoute{
		Dst: expectedRoutes[0].route.Dst.String(),
		Gw:  expectedRoutes[0].route.Gw.String(),
		Dev: expectedRoutes[0].dev,
	}, nil
}
