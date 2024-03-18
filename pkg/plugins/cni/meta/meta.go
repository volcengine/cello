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

package meta

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/google/renameio"
	"github.com/vishvananda/netlink"
)

type NetDevice struct {
	DeviceID string `json:"deviceID,omitempty"`
	Index    int    `json:"index,omitempty"`
	Name     string `json:"name,omitempty"`
	IPv4     *ip.IP `json:"ipV4,omitempty"`
	IPv6     *ip.IP `json:"ipV6,omitempty"`
	Mac      string `json:"mac,omitempty"`
}

func getIpRangesFromNetDevice(deviceID string, ipRangesSourceType string) ([]RangeSet, error) {
	netDevice, err := getNetDeviceWithCached(deviceID)
	if err != nil {
		return nil, fmt.Errorf("get netDevice %s addrs failed, %v", deviceID, err)
	}
	return getIPRanges(netDevice.IPv4, netDevice.IPv6, ipRangesSourceType)
}

func getNetDeviceWithCached(deviceID string) (*NetDevice, error) {
	// get from device first
	netDevice, err := getNetDevice(deviceID)
	if err == nil {
		if err = storeNetDeviceConfigCache(defaultCNIMetaDeviceDir, netDevice); err != nil {
			// cache failed, return error
			return nil, err
		}
		return netDevice, nil
	}
	lg.Warnf("get netDevice %s addr failed, try get from cache, %v", deviceID, err)

	// fallback to get from cache
	return loadNetDeviceConfigCache(defaultCNIMetaDeviceDir, deviceID)

}

func getNetDevice(deviceID string) (*NetDevice, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("deviceID is empty to get netDevice")
	}
	netDevice, err := getLink(deviceID)
	if err != nil {
		return nil, fmt.Errorf("get netDevice failed by deviceID %s, %v", deviceID, err)
	}
	var ipv4, ipv6 *ip.IP
	addrs, err := netlink.AddrList(netDevice, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("get netDevice addrs failed, %v", err)
	}
	// just support first ipv4 and first ipv6
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			isIPv6 := addr.IP.To4() == nil
			if !isIPv6 && ipv4 == nil && addr.IPNet != nil {
				ipv4 = &ip.IP{IPNet: *addr.IPNet}
			}
			if isIPv6 && ipv6 == nil && addr.IPNet != nil {
				ipv6 = &ip.IP{IPNet: *addr.IPNet}
			}
		}
	}

	if netDevice.Attrs() == nil {
		return nil, fmt.Errorf("get netDevice attr nil")
	}

	return &NetDevice{
		DeviceID: deviceID,
		Index:    netDevice.Attrs().Index,
		Name:     netDevice.Attrs().Name,
		IPv4:     ipv4,
		IPv6:     ipv6,
		Mac:      netDevice.Attrs().HardwareAddr.String(),
	}, nil
}

func getIPRanges(ipv4, ipv6 *ip.IP, ipRangesSourceType string) ([]RangeSet, error) {
	var ipv4Subnet, ipv6Subnet *net.IPNet
	var ranges []RangeSet
	var err error
	if ipv4 != nil {
		// ipv4 must contains cidr
		_, ipv4Subnet, err = net.ParseCIDR(ipv4.String())
		if err != nil {
			return nil, fmt.Errorf("parse ipv4 %s subnet failed, %v", ipv4.String(), err)
		}
	}
	if ipv6 != nil {
		// ipv6 must contains cidr
		_, ipv6Subnet, err = net.ParseCIDR(ipv6.String())
		if err != nil {
			return nil, fmt.Errorf("parse ipv6 %s subnet failed, %v", ipv6.String(), err)
		}
	}
	switch ipRangesSourceType {
	case IPRangeSourceNetDeviceSelf:
		if ipv4 != nil {
			ranges = append(ranges, RangeSet{
				Range{
					RangeStart: ipv4.IP,
					RangeEnd:   ipv4.IP,
					Subnet:     types.IPNet(*ipv4Subnet),
					Gateway:    nil, // gateway default is subnet first ip
				},
			})
		}
		if ipv6 != nil {
			ranges = append(ranges, RangeSet{
				Range{
					RangeStart: ipv6.IP,
					RangeEnd:   ipv6.IP,
					Subnet:     types.IPNet(*ipv6Subnet),
					Gateway:    nil,
				},
			})
		}
		return ranges, nil
	case IpRangeSourceNetDeviceSubnet:
		if ipv4 != nil {
			start := ip.NextIP(ipv4.IP)
			if !ipv4Subnet.Contains(start) || ipv4.IP.Equal(lastIP(*ipv4Subnet)) {
				return nil, fmt.Errorf("invalid ipv4 range {subnet: %s, rangeStart: %s}", ipv4Subnet.String(), start.String())
			}
			ranges = append(ranges, RangeSet{
				Range{
					RangeStart: start, // skip current device ip
					RangeEnd:   nil,
					Subnet:     types.IPNet(*ipv4Subnet),
					Gateway:    nil,
				},
			})
		}
		if ipv6 != nil {
			start := ip.NextIP(ipv6.IP)
			if !ipv6Subnet.Contains(start) {
				return nil, fmt.Errorf("invalid ipv6 range {subnet: %s, rangeStart: %s}", ipv6Subnet.String(), start.String())
			}
			ranges = append(ranges, RangeSet{
				Range{
					RangeStart: start, // skip current device ip
					RangeEnd:   nil,
					Subnet:     types.IPNet(*ipv6Subnet),
					Gateway:    nil,
				},
			})
		}
		return ranges, nil
	default:
		return nil, fmt.Errorf("unknown ipRangesSourceType %s for netDevice", ipRangesSourceType)
	}
}

func loadNetDeviceConfigCache(dirPath string, deviceID string) (*NetDevice, error) {
	var netDevice = NetDevice{}
	file := path.Join(dirPath, deviceID)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read netDevice cached config file %s failed, %v", file, err)
	}
	if err = json.Unmarshal(data, &netDevice); err != nil {
		return nil, fmt.Errorf("unmarshal netDevice cached config file %s failed, %v", file, err)
	}

	return &netDevice, nil
}

func storeNetDeviceConfigCache(dirPath string, device *NetDevice) error {
	if err := os.MkdirAll(dirPath, 0750); err != nil {
		return fmt.Errorf("make cache dir %s failed, %v", dirPath, err)
	}
	file := path.Join(dirPath, device.DeviceID)
	data, err := json.Marshal(device)
	if err != nil {
		return fmt.Errorf("marshal netDevice %v failed, %v", device, err)
	}
	if err = renameio.WriteFile(file, data, 0640); err != nil {
		return fmt.Errorf("write netDevice %s cache to %s failed, %v", device.DeviceID, file, err)
	}

	return nil
}
