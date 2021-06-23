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

package cello

import (
	"fmt"
	"strconv"

	cniip "github.com/containernetworking/plugins/pkg/ip"

	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/pbrpc"
)

func buildEndpointFromNetworkInterfaceConfig(cniConfig *types.NetConf, ifName string) (*pbrpc.CreateEndpointResponse, error) {
	if cniConfig.RuntimeConfig.NetworkInterfaceConfig == nil {
		return nil, fmt.Errorf("runtimeConfig com.volcengine.k8s.network-interface is nil")
	}
	if ifName == "" {
		return nil, fmt.Errorf("ifName empty for remote IPAM")
	}
	networkInterfaceConfig := cniConfig.RuntimeConfig.NetworkInterfaceConfig
	switch networkInterfaceConfig.Type {
	case types.NetworkInterfaceConfigTypeTrunk:
		return buildTrunkEndpointFromNetworkInterfaceConfig(networkInterfaceConfig, ifName)
	default:
		return nil, fmt.Errorf("runtimeConfit com.volcengine.k8s.network-interface type %s not support", networkInterfaceConfig.Type)
	}
}

func buildTrunkEndpointFromNetworkInterfaceConfig(runtimeConfig *types.NetworkInterfaceConfig, ifName string) (*pbrpc.CreateEndpointResponse, error) {
	if runtimeConfig == nil || runtimeConfig.Trunk == nil {
		return nil, fmt.Errorf("runtimeConfig com.volcengine.k8s.network-interface trunk is nil")
	}
	if runtimeConfig.Trunk.TrunkMac == "" || runtimeConfig.Trunk.VlanID == "" || runtimeConfig.Mac == "" || len(runtimeConfig.IPs) == 0 || len(runtimeConfig.IPs) > 2 {
		return nil, fmt.Errorf("invalid runtimeConfig for remote IPAM. %v", runtimeConfig)
	}
	vlanID, err := strconv.Atoi(runtimeConfig.Trunk.VlanID)
	if err != nil || vlanID < 0 {
		return nil, fmt.Errorf("invalid runtimeConfig for remote IPAM. convert vlan id %s to int failed, %v", runtimeConfig.Trunk.VlanID, err)
	}
	ips := runtimeConfig.IPs
	var ipv4, ipv6 string
	var ipv4Gateway, ipv6Gateway string
	for _, ip := range ips {
		subnet := cniip.Network(&ip.IPNet)
		if subnet == nil {
			return nil, fmt.Errorf("invalid runtimeConfig ips for remote IPAM. get subnet failed. %v", ip)
		}
		gateway := cniip.NextIP(subnet.IP)
		if !subnet.Contains(gateway) {
			return nil, fmt.Errorf("invalid runtimeConfig ips for remote IPAM. get gateway failed, ip: %v, subnet: %v, gateway: %v", ip, subnet, gateway)
		}
		if ip.ToIP().To4() == nil {
			if ipv6 != "" {
				return nil, fmt.Errorf("invalid runtimeConfig ips, only support one ipv6. %v", ips)
			}
			ipv6 = ip.String()
			ipv6Gateway = gateway.String()
		} else {
			if ipv4 != "" {
				return nil, fmt.Errorf("invalid runtimeConfig ips, only support one ipv4. %v", ips)
			}
			ipv4 = ip.String()
			ipv4Gateway = gateway.String()
		}
	}
	return &pbrpc.CreateEndpointResponse{
		IfType: pbrpc.IfType_TypeENIExclusive,
		Interfaces: []*pbrpc.NetworkInterface{
			{
				ENI: &pbrpc.ENI{
					ID:          "",
					Mac:         runtimeConfig.Trunk.TrunkMac,
					IPv4Gateway: ipv4Gateway,
					IPv6Gateway: ipv6Gateway,
					GatewayMac:  "",
					Subnet:      nil,
					Trunk:       true,
					Vid:         uint32(vlanID),
					SlaveMac:    runtimeConfig.Mac,
				},
				IPv4Addr:     ipv4,
				IPv6Addr:     ipv6,
				IfName:       ifName,
				ExtraRoutes:  nil,
				DefaultRoute: false,
			},
		},
	}, nil
}
