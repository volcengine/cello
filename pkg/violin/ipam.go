// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package violin

import (
	"fmt"
	"net"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/maps"
	utilsnet "k8s.io/utils/net"

	"github.com/volcengine/cello/pkg/plugins/ipam/cidr"
	"github.com/volcengine/cello/pkg/utils/device"
)

type IPManager struct {
	ipams      *cidr.AllocatorGroup
	devices    map[string]device.NetDevice
	pciDevices map[string]device.NetDevice
}

func NewIPManager(networks *NetworkConfig) (*IPManager, error) {
	devices := make(map[string]device.NetDevice)
	pciDevices := make(map[string]device.NetDevice)
	ipamConfig := &cidr.Config{
		DataDir: *networks.IpamStoreDir,
		Ranges:  map[string]*allocator.RangeSet{},
	}
	for _, devNet := range networks.Devices {
		dev, err := device.GetDeviceByName(devNet.DeviceName)
		if err != nil {
			return nil, fmt.Errorf("device %v not found", devNet.DeviceName)
		}
		devices[devNet.DeviceName] = dev
		if dev.IsPciDevice() {
			pciDevices[dev.PciId()] = dev
		}

		ranges := make([]allocator.Range, 0)

		switch devNet.IpamMode {
		case IPAMStatic:
			//TODO：support static IPAM.
			panic("not implemented")
		case IPAMRange:
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
		default:
			if len(devNet.Ranges) == 0 {
				addrs, err := device.GetRangeFromDevice(devNet.DeviceName)
				if err != nil {
					return nil, fmt.Errorf("failed to get device CIDR %w", err)
				}
				start, network := getAvailableCIDR(addrs)
				if start == nil || start.IsMulticast() {
					return nil, fmt.Errorf("invalid start address: %v", start)
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
	}

	err := cidr.PrepareConfig(ipamConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPAM Config %w", err)
	}

	ipam, err := cidr.NewAllocatorGroup(ipamConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to init allocator group %w", err)
	}
	return &IPManager{
		ipams:      ipam,
		devices:    devices,
		pciDevices: pciDevices,
	}, nil

}

func (mgr *IPManager) ListDevices() []device.NetDevice {
	return maps.Values(mgr.devices)
}

func (mgr *IPManager) DeviceById(id string) (device.NetDevice, bool) {
	dev, exist := mgr.pciDevices[id]
	return dev, exist
}

func (mgr *IPManager) DeviceByName(name string) (device.NetDevice, bool) {
	dev, exist := mgr.devices[name]
	return dev, exist
}

func getAvailableCIDR(addrs []netlink.Addr) (start net.IP, subnet *net.IPNet) {
	for i := range addrs {
		if addrs[i].IP.IsGlobalUnicast() {
			ipAddr, network, err := net.ParseCIDR(addrs[i].IPNet.String())
			if err != nil {
				return ip.NextIP(ipAddr), network
			}
		}
	}

	for i := range addrs {
		if utilsnet.IsIPv4CIDR(addrs[i].IPNet) {
			ipAddr, network, err := net.ParseCIDR(addrs[i].IPNet.String())
			if err != nil {
				return ip.NextIP(ipAddr), network
			}
		}
	}

	ipAddr, network, _ := net.ParseCIDR(addrs[0].IPNet.String())
	return ip.NextIP(ipAddr), network
}
