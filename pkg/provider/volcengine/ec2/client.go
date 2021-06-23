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
)

type APIGroupENI interface {
	// CreateNetworkInterface create a NetworkInterface
	CreateNetworkInterface(input *vpc.CreateNetworkInterfaceInput) (*vpc.CreateNetworkInterfaceOutput, error)

	// AttachNetworkInterface attach a NetworkInterface which status is available to ecs instance
	AttachNetworkInterface(input *vpc.AttachNetworkInterfaceInput) (*vpc.AttachNetworkInterfaceOutput, error)

	// DetachNetworkInterface detach a NetworkInterface which status is inuse from ecs instance
	DetachNetworkInterface(input *vpc.DetachNetworkInterfaceInput) (*vpc.DetachNetworkInterfaceOutput, error)

	// DeleteNetworkInterface delete a NetworkInterface which status is available
	DeleteNetworkInterface(input *vpc.DeleteNetworkInterfaceInput) (*vpc.DeleteNetworkInterfaceOutput, error)

	// DescribeNetworkInterfaces describe NetworkInterfaces according to input
	DescribeNetworkInterfaces(input *vpc.DescribeNetworkInterfacesInput) (*vpc.DescribeNetworkInterfacesOutput, error)

	// DescribeNetworkInterfaceAttributes return attributes of specified NetworkInterface
	DescribeNetworkInterfaceAttributes(input *vpc.DescribeNetworkInterfaceAttributesInput) (*DescribeNetworkInterfaceAttributesOutput, error)

	// AssignPrivateIpAddress assign private ipv4 addresses for specified NetworkInterface
	AssignPrivateIpAddress(input *vpc.AssignPrivateIpAddressesInput) (*vpc.AssignPrivateIpAddressesOutput, error)

	// UnAssignPrivateIpAddress unAssign private ipv4 addresses for specified NetworkInterface
	UnAssignPrivateIpAddress(input *vpc.UnassignPrivateIpAddressesInput) (*vpc.UnassignPrivateIpAddressesOutput, error)

	// AssignIpv6Addresses assign private ipv6 addresses for specified NetworkInterface
	AssignIpv6Addresses(input *AssignIpv6AddressesInput) (*AssignIpv6AddressesOutput, error)

	// UnassignIpv6Addresses unAssign private ipv6 addresses for specified NetworkInterface
	UnassignIpv6Addresses(input *UnassignIpv6AddressesInput) (*UnassignIpv6AddressesOutput, error)
}

type APIGroupSubnet interface {
	// DescribeSubnets describe Subnets according to input
	DescribeSubnets(input *vpc.DescribeSubnetsInput) (*DescribeSubnetsOutput, error)

	// DescribeSubnetAttributes return attributes of specified Subnet
	DescribeSubnetAttributes(input *vpc.DescribeSubnetAttributesInput) (*DescribeSubnetAttributesOutput, error)
}

type APIGroupECS interface {
	// DescribeInstances describe Instances according to input
	DescribeInstances(input *ecs.DescribeInstancesInput) (*ecs.DescribeInstancesOutput, error)

	// DescribeInstanceTypes describe InstanceTypes according to input
	DescribeInstanceTypes(input *ecs.DescribeInstanceTypesInput) (*ecs.DescribeInstanceTypesOutput, error)
}

type EC2 interface {
	APIGroupENI
	APIGroupSubnet
	APIGroupECS
}
