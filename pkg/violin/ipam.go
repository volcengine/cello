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

package violin

import (
	"fmt"
	"net"
	"strings"
	"sync"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/vishvananda/netlink"
	utilsnet "k8s.io/utils/net"

	"github.com/volcengine/cello/pkg/plugins/ipam/cidr"
	"github.com/volcengine/cello/pkg/utils/device"
)

type IPManager struct {
	ipams        *cidr.AllocatorGroup
	devices      *sync.Map
	devicePrefix string
	ipamStore    string
}

func NewIPManager(networks *NetworkConfig) (*IPManager, error) {
	var devList []NetDevConfig

	if networks.DevicePrefix != nil {
		devList = make([]NetDevConfig, 0)
		links, err := device.ListLinksWithPrefix(*networks.DevicePrefix)
		if err != nil {
			return nil, fmt.Errorf("Failed to get devices with prefix: %v due to %v\n", *networks.DevicePrefix, err)
		}
		fmt.Println("found devices:")
		for _, dev := range links {
			fmt.Println(dev.Attrs().Name)
			devList = append(devList, NetDevConfig{
				DeviceName: dev.Attrs().Name,
				IpamMode:   DeviceRange,
			})
		}
		networks.Devices = append(networks.Devices, devList...)
	}

	devices := &sync.Map{}
	ipamConfig := &cidr.Config{
		DataDir: *networks.IpamStoreDir,
		Ranges:  map[string]*allocator.RangeSet{},
	}
	for _, devNet := range networks.Devices {
		dev, err := device.GetDeviceByName(devNet.DeviceName)
		if err != nil {
			return nil, fmt.Errorf("device %v not found", devNet.DeviceName)
		}

		ranges := make([]allocator.Range, 0)
		switch devNet.IpamMode {
		case StaticRange:
			for _, iprange := range devNet.Ranges {
				ranges = append(ranges,
					allocator.Range{
						RangeStart: iprange.Start,
						RangeEnd:   iprange.End,
						Subnet: cniTypes.IPNet{
							IP:   iprange.Subnet.IP,
							Mask: iprange.Subnet.Mask,
						},
						Gateway: iprange.Gateway,
					})
			}
			fallthrough
		case DeviceRange:
			fallthrough
		default:
			if len(devNet.Ranges) == 0 {
				addrs, err := device.GetAddrsFromDevice(devNet.DeviceName)
				if err != nil {
					return nil, fmt.Errorf("failed to get device CIDR %w", err)
				}
				start, network, err := availableCIDR(addrs)
				if err != nil || start == nil {
					continue
				}

				ranges = append(ranges, allocator.Range{
					RangeStart: start,
					Subnet: cniTypes.IPNet{
						IP:   network.IP,
						Mask: network.Mask,
					},
				})
			}
			var rangeset allocator.RangeSet
			rangeset = ranges
			ipamConfig.Ranges[devNet.DeviceName] = &rangeset
		}

		devices.Store(dev.IfName(), dev)
		if dev.IsPciDevice() {
			devices.Store(dev.PciId(), dev)
		}
	}

	ipam, err := cidr.NewAllocatorGroup(ipamConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to init allocator group %w", err)
	}
	return &IPManager{
		ipams:        ipam,
		devices:      devices,
		devicePrefix: *networks.DevicePrefix,
		ipamStore:    *networks.IpamStoreDir,
	}, nil

}

func (mgr *IPManager) ListDevices() []device.NetDevice {
	devs := make([]device.NetDevice, 0)
	mgr.devices.Range(func(key, value any) bool {
		devs = append(devs, &device.NetDev{
			PciAddr: value.(device.NetDevice).PciId(),
			NetName: value.(device.NetDevice).IfName(),
			Mac:     value.(device.NetDevice).HwAddr(),
		})
		return false
	})
	return devs
}

func (mgr *IPManager) DeviceByID(id string) (device.NetDevice, error) {
	var dev device.NetDevice
	d, exist := mgr.devices.Load(strings.Trim(id, "\""))
	if !exist {
		names, err := device.GetNetNamesByDeviceId(id)
		if err != nil {
			return nil, fmt.Errorf("device %s not found %w", id, err)
		}
		for _, name := range names {
			if strings.HasPrefix(name, mgr.devicePrefix) {
				dev, err = device.GetDeviceByName(name)
				if err != nil {
					return nil, fmt.Errorf("device id: %s name: %s not found %w", id, name, err)
				}
				addrs, err := device.GetAddrsFromDevice(dev.IfName())
				if err != nil {
					return nil, err
				}
				startIP, subnet, err := availableCIDR(addrs)
				if err != nil {
					return nil, err
				}
				rangeset := []allocator.Range{
					{
						RangeStart: startIP,
						Subnet: cniTypes.IPNet{
							IP:   subnet.IP,
							Mask: subnet.Mask,
						},
					},
				}
				err = mgr.ipams.AddRangeSet(dev.IfName(), mgr.ipamStore, (*allocator.RangeSet)(&rangeset))
				if err != nil {
					return nil, fmt.Errorf("faild to add range for dev %v range: %v err: %w",
						dev.IfName(), rangeset, err)
				}

				mgr.devices.LoadOrStore(dev.IfName(), dev)
				if dev.IsPciDevice() {
					mgr.devices.LoadOrStore(dev.PciId(), dev)
				}
				break
			}
		}
	} else {
		dev = d.(device.NetDevice)
	}
	return dev.(device.NetDevice), nil
}

func availableCIDR(addrs []netlink.Addr) (start net.IP, subnet *net.IPNet, err error) {
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("no available CIDR found")
	}
	for i := range addrs {
		if addrs[i].IP.IsGlobalUnicast() {
			ipAddr, network, err := net.ParseCIDR(addrs[i].IPNet.String())
			if err != nil {
				return ip.NextIP(ipAddr), network, nil
			}
		}
	}

	for i := range addrs {
		if utilsnet.IsIPv4CIDR(addrs[i].IPNet) {
			ipAddr, network, err := net.ParseCIDR(addrs[i].IPNet.String())
			if err != nil {
				return ip.NextIP(ipAddr), network, nil
			}
		}
	}

	ipAddr, network, err := net.ParseCIDR(addrs[0].IPNet.String())
	return ip.NextIP(ipAddr), network, err
}
