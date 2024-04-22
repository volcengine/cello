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

package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/volcengine/cello/pkg/utils/logger"
)

// Metadata APIs
const (
	region           = "region_id"
	availabilityZone = "availability_zone"
	instanceID       = "instance_id"
	instanceType     = "instance_type_id"
	vpc              = "vpc_id"
	vpcCIDR          = "vpc_cidr_block"
	macs             = "network/interfaces/macs"
	instanceMAC      = "mac"
	eniID            = "network/interfaces/macs/%s/network_interface_id"
	primaryIP        = "network/interfaces/macs/%s/primary_ip_address"
	gatewayIP        = "network/interfaces/macs/%s/gateway"
	ips              = "network/interfaces/macs/%s/private_ip_addresses"
	networkInfo      = "network/interfaces/macs/%s/network_info"
	iam              = "iam/security_credentials/"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "metadata"})

type ClientWrapper struct {
	getter Getter
}

func NewClientWrapper(getter Getter) ClientWrapper {
	return ClientWrapper{
		getter: getter,
	}
}

// Region returns region id of instance, eg: cn-beijing.
func (client ClientWrapper) Region(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetRegion", region)
	if err != nil {
		return "", fmt.Errorf("failed to get region id: %w", err)
	}
	return string(data), err
}

// AvailabilityZone returns availability zone id of instance, eg: cn-beijing-a.
func (client ClientWrapper) AvailabilityZone(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetAvailabilityZone", availabilityZone)
	if err != nil {
		return "", fmt.Errorf("failed to get az id: %w", err)
	}
	return string(data), err
}

// InstanceID returns instance id.
func (client ClientWrapper) InstanceID(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetInstanceID", instanceID)
	if err != nil {
		return "", fmt.Errorf("failed to get instance id: %w", err)
	}
	return string(data), err
}

// InstanceType returns instance type id, eg: ecs.g1ie.xlarge.
func (client ClientWrapper) InstanceType(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetInstanceType", instanceType)
	if err != nil {
		return "", fmt.Errorf("failed to get instance type: %w", err)
	}
	return string(data), err
}

// VPCID returns vpc id of instance's primary interface.
func (client ClientWrapper) VPCID(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetVpcID", vpc)
	if err != nil {
		return "", fmt.Errorf("failed to get vpc_id: %w", err)
	}
	return string(data), err
}

// VPCCidrBlock returns CIDR block of instance's primary interface， eg: 172.16.0.0/12.
func (client ClientWrapper) VPCCidrBlock(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetVpcCidr", vpcCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to get vpc_cidr: %w", err)
	}
	return string(data), err
}

// MacAddresses  returns a list of interfaces' mac address.
func (client ClientWrapper) MacAddresses(ctx context.Context) ([]string, error) {
	data, err := client.getter.Get(ctx, "", macs)
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}
	return strings.Split(string(data), "\n"), nil
}

// PrimaryMacAddress returns primary interface's mac address.
func (client ClientWrapper) PrimaryMacAddress(ctx context.Context) (string, error) {
	data, err := client.getter.Get(ctx, "GetPrimaryENIMac", instanceMAC)
	if err != nil {
		return "", fmt.Errorf("failed to get primary interface: %w", err)
	}
	return string(data), err
}

// InterfaceID returns primary interface's ip address.
func (client ClientWrapper) InterfaceID(ctx context.Context, mac string) (string, error) {
	addr, err := client.getter.Get(ctx, "GetENIID", fmt.Sprintf(eniID, mac))
	if err != nil {
		return "", fmt.Errorf("failed to get interface %v primary ip: %w", mac, err)
	}
	return string(addr), nil
}

// InterfacePrimaryIP returns primary interface's ip address.
func (client ClientWrapper) InterfacePrimaryIP(ctx context.Context, mac string) (net.IP, error) {
	addr, err := client.getter.Get(ctx, "GetENIPrimaryIP", fmt.Sprintf(primaryIP, mac))
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %v primary ip: %w", mac, err)
	}

	return net.ParseIP(string(addr)), nil
}

// InterfaceGatewayIP returns gateway ip of interface.
func (client ClientWrapper) InterfaceGatewayIP(ctx context.Context, mac string) (net.IP, error) {
	addr, err := client.getter.Get(ctx, "GetENIIPv4Gateway", fmt.Sprintf(gatewayIP, mac))
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway ip for interface %v: %w", mac, err)
	}
	return net.ParseIP(string(addr)), err
}

// InterfaceSecondaryIPs returns secondary ips of interface.
func (client ClientWrapper) InterfaceSecondaryIPs(ctx context.Context, mac string) ([]net.IP, error) {
	addrs, err := client.getter.Get(ctx, "GetENIIPv4s", fmt.Sprintf(ips, mac))
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway ip for interface %v: %w", mac, err)
	}
	ips := make([]net.IP, 0)

	for _, addr := range strings.Split(string(addrs), "\n") {
		if len(addr) == 0 {
			continue
		}
		ips = append(ips, net.ParseIP(addr))
	}

	return ips, err
}

// InterfaceInfo returns network information of interface.
func (client ClientWrapper) InterfaceInfo(ctx context.Context, mac string) (*InterfaceInfo, error) {
	data, err := client.getter.Get(ctx, "GetNetworkInfo", fmt.Sprintf(networkInfo, mac))
	if err != nil {
		return nil, err
	}
	var nicInfo InterfaceInfo
	err = json.Unmarshal(data, &nicInfo)

	for _, addr := range strings.Split(nicInfo.PrivateIpv4s, "\n") {
		if len(addr) == 0 {
			continue
		}
		nicInfo.PrivateIPAddresses = append(nicInfo.PrivateIPAddresses, addr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get network inteface %v information: %w", mac, err)
	}
	return &nicInfo, err
}

// STSCredential returns Credential Token from IAM ServiceToken Service.
func (client ClientWrapper) STSCredential(ctx context.Context, role string) (string, error) {
	if len(role) == 0 {
		return "", fmt.Errorf("invalid role name")
	}
	data, err := client.getter.Get(ctx, "GetIamRoleCredential", path.Join(iam, role))
	if err != nil {
		return "", err
	}

	return string(data), nil
}
