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
	"time"

	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/utils/ip"
)

const (
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
	GetMetadata(ctx context.Context, path string) (string, error)
}

// EC2MetadataWrapper wrap the interface of metadata to get information from metadata service and monitor for errors.
type EC2MetadataWrapper struct {
	EC2MetadataIface
}

// GetPrimaryENIMac get mac of primary eni from metadata.
func (meta EC2MetadataWrapper) GetPrimaryENIMac(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, "mac")
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetPrimaryENIMac", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetPrimaryENIMac", err)
	}
	return data, err
}

// GetAvailabilityZone get az of instance from metadata.
func (meta EC2MetadataWrapper) GetAvailabilityZone(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, azPath)
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetAvailabilityZone", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetAvailabilityZone", err)
	}
	return data, err
}

// GetENIsMacs get all macs of ENIs which attached the instance from metadata.
func (meta EC2MetadataWrapper) GetENIsMacs(ctx context.Context) ([]string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, enisMacsPath)
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIsMacs", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIsMacs", err)
		return nil, fmt.Errorf("get ENIs failed : %w", err)
	}
	return strings.Split(data, "\n"), nil
}

// GetInstanceID get the instance ID from metadata.
func (meta EC2MetadataWrapper) GetInstanceID(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, "instance_id")
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetInstanceID", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetInstanceID", err)
	}
	return data, err
}

// GetInstanceType get the instance type from metadata.
func (meta EC2MetadataWrapper) GetInstanceType(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, "instance_type")
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetInstanceType", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetInstanceType", err)
	}
	return data, err
}

// GetRegionID get the region ID of instance from metadata.
func (meta EC2MetadataWrapper) GetRegionID(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, "region_id")
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetRegionID", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetRegionID", err)
	}
	return data, err
}

// GetVpcId get the vpc ID of ECS instance from metadata.
func (meta EC2MetadataWrapper) GetVpcId(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, vpcIdPath)
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetVpcId", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetVpcId", err)
	}
	return data, err
}

// GetVpcCidr get the vpc Cidr that belongs to the ECS instance from metadata.
func (meta EC2MetadataWrapper) GetVpcCidr(ctx context.Context) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, vpcCidrPath)
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetVpcCidr", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetVpcCidr", err)
	}
	return data, err
}

// GetENIPrimaryIP get primary ip of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIPrimaryIP(ctx context.Context, mac string) (net.IP, error) {
	start := time.Now()
	addr, err := meta.GetMetadata(ctx, fmt.Sprintf(eniAddrPath, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIPrimaryIP", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIPrimaryIP", err)
		return nil, err
	}
	return ip.ParseIP(addr)
}

// GetENISubnetID get subnet id of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENISubnetID(ctx context.Context, mac string) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, fmt.Sprintf(eniSubnetIDPath, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENISubnetID", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENISubnetID", err)
	}
	return data, err
}

// GetENIID get id of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIID(ctx context.Context, mac string) (string, error) {
	start := time.Now()
	data, err := meta.GetMetadata(ctx, fmt.Sprintf(eniIDPath, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIID", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIID", err)
	}
	return data, err
}

// GetENIIPv4Gateway get ipv4 gateway of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIIPv4Gateway(ctx context.Context, mac string) (net.IP, error) {
	start := time.Now()
	gw, err := meta.GetMetadata(ctx, fmt.Sprintf(eniGatewayPath, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIGateway", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIGateway", err)
		return nil, err
	}
	return ip.ParseIP(gw)
}

// GetENIIPv6Gateway get ipv6 gateway of eni by mac from metadata
// TODO: metadata service currently does not support.
func (meta EC2MetadataWrapper) GetENIIPv6Gateway(ctx context.Context, mac string) (net.IP, error) {
	start := time.Now()
	gw, err := meta.GetMetadata(ctx, fmt.Sprintf(eniV6GatewayPath, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIGateway", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIGateway", err)
		return nil, err
	}
	return ip.ParseIP(gw)
}

// GetENISubnetCIDR get subnet cidr of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENISubnetCIDR(ctx context.Context, mac string) (*net.IPNet, error) {
	start := time.Now()
	cidr, err := meta.GetMetadata(ctx, fmt.Sprintf(eniSubnetCIDRPath, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENISubnetCIDR", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENISubnetCIDR", err)
		return nil, err
	}
	_, subnetCIDR, err := net.ParseCIDR(cidr)
	return subnetCIDR, err
}

// GetENIPrivateIPv4s get private ipv4s of eni by mac from metadata.
func (meta EC2MetadataWrapper) GetENIPrivateIPv4s(ctx context.Context, mac string) ([]net.IP, error) {
	start := time.Now()
	ipsStr, err := meta.GetMetadata(ctx, fmt.Sprintf(eniPrivateIPs, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIPrivateIPv4s", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIPrivateIPv4s", err)
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
	start := time.Now()
	ipsStr, err := meta.GetMetadata(ctx, fmt.Sprintf(eniPrivateIPv6s, mac))
	duration := metrics.MsSince(start)
	metrics.MetadataLatency.WithLabelValues("GetENIPrivateIPv6s", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err)).Observe(duration)
	if err != nil {
		metrics.MetadataErrInc("GetENIPrivateIPv6s", err)
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
