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

package metadata

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/volcengine/cello/pkg/utils/ip"
)

const (
	PrimaryEniMacPath = "mac"
	instanceIdPath    = "instance_id"
	instanceTypePath  = "instance_type"
	regionIdPath      = "region_id"
	azPath            = "availability_zone"
	vpcIdPath         = "vpc_id"
	vpcCidrPath       = "vpc_cidr_block"
	enisMacsPath      = "network/interfaces/macs"
	eniIDPath         = "network/interfaces/macs/%s/network_interface_id"
	eniAddrPath       = "network/interfaces/macs/%s/primary_ip_address"
	eniGatewayPath    = "network/interfaces/macs/%s/gateway"
	eniV6GatewayPath  = "network/interfaces/macs/%s/ipv6-gateway"
	eniPrivateIPs     = "network/interfaces/macs/%s/private_ipv4s"
	eniPrivateIPv6s   = "network/interfaces/macs/%s/private_ipv6s"
	eniSubnetIDPath   = "network/interfaces/macs/%s/subnet_id"
	eniSubnetCIDRPath = "network/interfaces/macs/%s/subnet_cidr_block"
)

// EC2MetadataIface interface of metadata.
type EC2MetadataIface interface {
	GetMetadata(ctx context.Context, sign, path string) (string, error)
}

// EC2MetadataWrapper wrap the interface of metadata to get information from metadata service and monitor for errors.
type EC2MetadataWrapper struct {
	EC2MetadataIface
}

// GetPrimaryENIMac get mac of primary eni from metadata.
func (meta EC2MetadataWrapper) GetPrimaryENIMac(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetPrimaryENIMac", PrimaryEniMacPath)
}

// GetAvailabilityZone get az of instance from metadata.
func (meta EC2MetadataWrapper) GetAvailabilityZone(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetAvailabilityZone", azPath)
}

// GetENIsMacs get all macs of ENIs which attached the instance from metadata.
// NOTICE: this will get all interfaces macs include rdma which unable to get any information,
// and other interfaces not created by cello, even cross-account interfaces
func (meta EC2MetadataWrapper) GetENIsMacs(ctx context.Context) ([]string, error) {
	data, err := meta.GetMetadata(ctx, "GetENIsMacs", enisMacsPath)
	if err != nil {
		return nil, fmt.Errorf("get ENIs failed : %w", err)
	}
	return strings.Split(data, "\n"), nil
}

// GetInstanceID get the instance ID from metadata.
func (meta EC2MetadataWrapper) GetInstanceID(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetInstanceID", instanceIdPath)
}

// GetInstanceType get the instance type from metadata.
func (meta EC2MetadataWrapper) GetInstanceType(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetInstanceType", instanceTypePath)
}

// GetRegionID get the region ID of instance from metadata.
func (meta EC2MetadataWrapper) GetRegionID(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetRegionID", regionIdPath)
}

// GetVpcId get the vpc ID of ECS instance from metadata.
func (meta EC2MetadataWrapper) GetVpcId(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetVpcId", vpcIdPath)
}

// GetVpcCidr get the vpc Cidr that belongs to the ECS instance from metadata.
func (meta EC2MetadataWrapper) GetVpcCidr(ctx context.Context) (string, error) {
	return meta.GetMetadata(ctx, "GetVpcCidr", vpcCidrPath)
}

// GetENIPrimaryIP get primary ip of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIPrimaryIP(ctx context.Context, mac string) (net.IP, error) {
	addr, err := meta.GetMetadata(ctx, "GetENIPrimaryIP", fmt.Sprintf(eniAddrPath, mac))
	if err != nil {
		return nil, err
	}
	return ip.ParseIP(addr)
}

// GetENISubnetID get subnet id of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENISubnetID(ctx context.Context, mac string) (string, error) {
	return meta.GetMetadata(ctx, "GetENISubnetID", fmt.Sprintf(eniSubnetIDPath, mac))
}

// GetENIID get id of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIID(ctx context.Context, mac string) (string, error) {
	return meta.GetMetadata(ctx, "GetENIID", fmt.Sprintf(eniIDPath, mac))

}

// GetENIIPv4Gateway get ipv4 gateway of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIIPv4Gateway(ctx context.Context, mac string) (net.IP, error) {
	gw, err := meta.GetMetadata(ctx, "GetENIIPv4Gateway", fmt.Sprintf(eniGatewayPath, mac))
	if err != nil {
		return nil, err
	}
	return ip.ParseIP(gw)
}

// GetENIIPv6Gateway get ipv6 gateway of eni by mac from metadata
// TODO: metadata service currently does not support.
func (meta EC2MetadataWrapper) GetENIIPv6Gateway(ctx context.Context, mac string) (net.IP, error) {
	gw, err := meta.GetMetadata(ctx, "GetENIIPv6Gateway", fmt.Sprintf(eniV6GatewayPath, mac))
	if err != nil {
		return nil, err
	}
	return ip.ParseIP(gw)
}

// GetENISubnetCIDR get subnet cidr of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENISubnetCIDR(ctx context.Context, mac string) (*net.IPNet, error) {
	cidr, err := meta.GetMetadata(ctx, "GetENISubnetCIDR", fmt.Sprintf(eniSubnetCIDRPath, mac))
	if err != nil {
		return nil, err
	}
	_, subnetCIDR, err := net.ParseCIDR(cidr)
	return subnetCIDR, err
}

// GetENIPrivateIPv4s get private ipv4s of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIPrivateIPv4s(ctx context.Context, mac string) ([]net.IP, error) {
	ipsStr, err := meta.GetMetadata(ctx, "GetENIPrivateIPv4s", fmt.Sprintf(eniPrivateIPs, mac))
	if err != nil {
		return nil, err
	}
	if len(ipsStr) == 0 {
		return nil, nil
	}
	addressStrList := strings.Split(ipsStr, "\n")
	ips, err := ip.ParseIPs(addressStrList)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// GetENIPrivateIPv6s get private ipv6s of eni by mac from metadata
// TODO: metadata service currently does not support.
func (meta EC2MetadataWrapper) GetENIPrivateIPv6s(ctx context.Context, mac string) ([]net.IP, error) {
	ipsStr, err := meta.GetMetadata(ctx, "GetENIPrivateIPv6s", fmt.Sprintf(eniPrivateIPv6s, mac))
	if err != nil {
		return nil, err
	}
	if len(ipsStr) == 0 {
		return nil, nil
	}
	addressStrList := strings.Split(ipsStr, "\n")
	ips, err := ip.ParseIPs(addressStrList)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// NewEC2MetadataWrapper return new EC2MetadataWrapper.
func NewEC2MetadataWrapper(m EC2MetadataIface) EC2MetadataWrapper {
	return EC2MetadataWrapper{m}
}

// FakeEC2Metadata fake EC2Metadata for test.
type FakeEC2Metadata map[string]interface{}

// GetMetadata get information from fake metadata service by path.
func (f FakeEC2Metadata) GetMetadata(_ context.Context, path string) (info string, err error) {
	result, ok := f[path]
	if !ok {
		return "", fmt.Errorf("%d page not found", http.StatusNotFound)
	}
	switch v := result.(type) {
	case string:
		return v, nil
	case error:
		return "", v
	default:
		panic(fmt.Sprintf("unknown test metadata value type %T for %s", result, path))
	}
}
