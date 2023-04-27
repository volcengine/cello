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

package ec2

import (
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
)

type AssignIpv6AddressesInput struct {
	_ struct{} `type:"structure"`

	Ipv6Address []*string `type:"list"`

	Ipv6AddressCount *int64 `type:"integer"`

	// NetworkInterfaceId is a required field
	NetworkInterfaceId *string `type:"string" required:"true"`
}

type AssignIpv6AddressesOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	Ipv6Set []*string `type:"list"`

	NetworkInterfaceId *string `type:"string"`

	RequestId *string `type:"string"`
}

type UnassignIpv6AddressesInput struct {
	_ struct{} `type:"structure"`

	// Ipv6Address is a required field
	Ipv6Address []*string `type:"list" required:"true"`

	// NetworkInterfaceId is a required field
	NetworkInterfaceId *string `type:"string" required:"true"`
}

type UnassignIpv6AddressesOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	RequestId *string `type:"string"`
}

type DescribeNetworkInterfaceAttributesOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	AccountId *string `type:"string"`

	CreatedAt *string `type:"string"`

	Description *string `type:"string"`

	DeviceId *string `type:"string"`

	IPv6Sets []*string `type:"list"`

	MacAddress *string `type:"string"`

	NetworkInterfaceId *string `type:"string"`

	NetworkInterfaceName *string `type:"string"`

	PortSecurityEnabled *bool `type:"boolean"`

	PrimaryIpAddress *string `type:"string"`

	PrivateIpAddresses []*string `type:"list"`

	PrivateIpSets *vpc.PrivateIpSetsForDescribeNetworkInterfaceAttributesOutput `type:"structure"`

	ProjectName *string `type:"string"`

	RequestId *string `type:"string"`

	SecurityGroupIds []*string `type:"list"`

	ServiceManaged *bool `type:"boolean"`

	Status *string `type:"string"`

	SubnetId *string `type:"string"`

	Tags []*vpc.TagForDescribeNetworkInterfaceAttributesOutput `type:"list"`

	Type *string `type:"string"`

	UpdatedAt *string `type:"string"`

	VpcId *string `type:"string"`

	VpcName *string `type:"string"`

	ZoneId *string `type:"string"`
}

type DescribeNetworkInterfacesOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	NetworkInterfaceSets []*NetworkInterfaceSetForDescribeNetworkInterfacesOutput `type:"list"`

	PageNumber *int64 `type:"integer"`

	PageSize *int64 `type:"integer"`

	RequestId *string `type:"string"`

	TotalCount *int64 `type:"integer"`
}

type NetworkInterfaceSetForDescribeNetworkInterfacesOutput struct {
	_ struct{} `type:"structure"`

	AccountId *string `type:"string"`

	AssociatedElasticIp *vpc.AssociatedElasticIpForDescribeNetworkInterfacesOutput `type:"structure"`

	CreatedAt *string `type:"string"`

	Description *string `type:"string"`

	DeviceId *string `type:"string"`

	IPv6Sets []*string `type:"list"`

	MacAddress *string `type:"string"`

	NetworkInterfaceId *string `type:"string"`

	NetworkInterfaceName *string `type:"string"`

	PortSecurityEnabled *bool `type:"boolean"`

	PrimaryIpAddress *string `type:"string"`

	PrivateIpAddresses []*string `type:"list"`

	PrivateIpSets *vpc.PrivateIpSetsForDescribeNetworkInterfacesOutput `type:"structure"`

	ProjectName *string `type:"string"`

	SecurityGroupIds []*string `type:"list"`

	ServiceManaged *bool `type:"boolean"`

	Status *string `type:"string"`

	SubnetId *string `type:"string"`

	Tags []*vpc.TagForDescribeNetworkInterfacesOutput `type:"list"`

	Type *string `type:"string"`

	UpdatedAt *string `type:"string"`

	VpcId *string `type:"string"`

	VpcName *string `type:"string"`

	ZoneId *string `type:"string"`
}

type SubnetForDescribeSubnetsOutput struct {
	_ struct{} `type:"structure"`

	AccountId *string `type:"string"`

	AvailableIpAddressCount *int64 `type:"integer"`

	CidrBlock *string `type:"string"`

	CreationTime *string `type:"string"`

	Description *string `type:"string"`

	Ipv6CidrBlock *string `type:"string"`

	NetworkAclId *string `type:"string"`

	ProjectName *string `type:"string"`

	RouteTable *vpc.RouteTableForDescribeSubnetsOutput `type:"structure"`

	Status *string `type:"string"`

	SubnetId *string `type:"string"`

	SubnetName *string `type:"string"`

	TotalIpv4Count *int64 `type:"integer"`

	UpdateTime *string `type:"string"`

	VpcId *string `type:"string"`

	ZoneId *string `type:"string"`
}

type DescribeSubnetsOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	PageNumber *int64 `type:"integer"`

	PageSize *int64 `type:"integer"`

	RequestId *string `type:"string"`

	Subnets []*SubnetForDescribeSubnetsOutput `type:"list"`

	TotalCount *int64 `type:"integer"`
}

type DescribeSubnetAttributesOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	AccountId *string `type:"string"`

	AvailableIpAddressCount *int64 `type:"integer"`

	CidrBlock *string `type:"string"`

	CreationTime *string `type:"string"`

	Description *string `type:"string"`

	Ipv6CidrBlock *string `type:"string"`

	NetworkAclId *string `type:"string"`

	ProjectName *string `type:"string"`

	RequestId *string `type:"string"`

	RouteTable *vpc.RouteTableForDescribeSubnetAttributesOutput `type:"structure"`

	Status *string `type:"string"`

	SubnetId *string `type:"string"`

	SubnetName *string `type:"string"`

	TotalIpv4Count *int64 `type:"integer"`

	UpdateTime *string `type:"string"`

	VpcId *string `type:"string"`

	ZoneId *string `type:"string"`
}

type DescribeInstanceTypesOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	InstanceTypes []*InstanceTypeForDescribeInstanceTypesOutput `type:"list"`

	NextToken *string `type:"string"`

	PageNumber *int32 `type:"int32"`

	PageSize *int32 `type:"int32"`

	TotalCount *int32 `type:"int32"`
}

type InstanceTypeForDescribeInstanceTypesOutput struct {
	_ struct{} `type:"structure"`

	Architecture *string `type:"string"`

	BaselineCredit *int64 `type:"int64"`

	ComputeFactor *int32 `type:"int32"`

	Cpu *int32 `type:"int32"`

	Gpu *ecs.GpuForDescribeInstanceTypesOutput `type:"structure"`

	Id *string `type:"string"`

	InitialCredit *int64 `type:"int64"`

	InstanceTypeFamily *string `type:"string"`

	InstanceTypeId *string `type:"string"`

	IsSupportRiCreate *bool `type:"boolean"`

	IsSupportRiModify *bool `type:"boolean"`

	IsSupportSpot *bool `type:"boolean"`

	LocalVolumes []*ecs.LocalVolumeForDescribeInstanceTypesOutput `type:"list"`

	Mem *int32 `type:"int32"`

	Memory *ecs.MemoryForDescribeInstanceTypesOutput `type:"structure"`

	NetKppsQuota *int32 `type:"int32"`

	NetMbpsQuota *int32 `type:"int32"`

	NetSessionQuota *int32 `type:"int32"`

	Network *ecs.NetworkForDescribeInstanceTypesOutput `type:"structure"`

	NetworkInterfaceNumQuota *int32 `type:"int32"`

	NetworkInterfaceTotalNumQuota *int32 `type:"int32"`

	PrivateIpQuota *int32 `type:"int32"`

	Processor *ecs.ProcessorForDescribeInstanceTypesOutput `type:"structure"`

	Rdma *ecs.RdmaForDescribeInstanceTypesOutput `type:"structure"`

	TrunkNetworkInterfaceSupported *bool `type:"boolean"`

	Type *string `type:"string"`

	Volume *ecs.VolumeForDescribeInstanceTypesOutput `type:"structure"`

	VolumeTypes []*string `type:"list"`
}

type CreateNetworkInterfaceInput struct {
	_ struct{} `type:"structure"`

	ClientToken *string `type:"string"`

	Description *string `min:"1" max:"255" type:"string"`

	NetworkInterfaceName *string `min:"1" max:"128" type:"string"`

	PortSecurityEnabled *bool `type:"boolean"`

	PrimaryIpAddress *string `type:"string"`

	PrivateIpAddress []*string `type:"list"`

	ProjectName *string `type:"string"`

	SecondaryPrivateIpAddressCount *int64 `type:"integer"`

	// SecurityGroupIds is a required field
	SecurityGroupIds []*string `type:"list" required:"true"`

	// SubnetId is a required field
	SubnetId *string `type:"string" required:"true"`

	Tags []*vpc.TagForCreateNetworkInterfaceInput `type:"list"`

	Type *string `type:"string" enum:"TypeForCreateNetworkInterfaceInput"`
}
