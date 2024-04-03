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

package mock

import (
	"context"
	"errors"

	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
)

// Raw data from metadata response.
const (
	Role           = "ServiceRoleForVolcECS"
	RegionId       = "cn-beijing"
	AzId           = "cn-beijing-a"
	InstanceId     = "i-1234567890"
	InstanceTypeId = "ecs.g1ie.xlarge"
	VpcId          = "vpc-1234567890"
	VpcCidrBlock   = "172.16.0.0/16"
	Macs           = "00:16:3e:15:0b:69\n00:16:3e:16:f0:f9\n00:16:3e:36:fe:9c\n00:16:3e:65:71:29"
	Mac            = "00:16:3e:16:f0:f9"
	GatewayIP      = "172.16.1.1"
	PrimaryIP      = "172.16.1.9"
	InterfaceId    = "eni-rs2vnlglkhdsv0x57806fyj"
	SubnetId       = "subnet-13fic2voyqk1s3n6nu4ysssg5"
	SubnetCidr     = "172.16.1.0/24"
	PrivateIps     = "172.16.1.10\n172.16.1.17\n172.16.1.18\n172.16.1.19\n172.16.1.20\n172.16.1.21\n172.16.1.22\n172.16.1.28\n172.16.1.29\n172.16.1.38\n172.16.1.39\n172.16.1.40\n172.16.1.41\n172.16.1.42"
	NetworkInfo    = "{\"NetworkInterfaceId\":\"eni-rs2vnlglkhdsv0x57806fyj\",\"PrimaryIpAddress\":\"172.16.1.9\",\"Gateway\":\"172.16.1.1\",\"SubnetId\":\"subnet-13fic2voyqk1s3n6nu4ysssg5\",\"SubnetCidrBlock\":\"172.16.1.0/24\",\"PrivateIpv4s\":\"172.16.1.10\\n172.16.1.17\\n172.16.1.18\\n172.16.1.19\\n172.16.1.20\\n172.16.1.21\\n172.16.1.22\\n172.16.1.28\\n172.16.1.29\\n172.16.1.38\\n172.16.1.39\\n172.16.1.40\\n172.16.1.41\\n172.16.1.42\"}"
	ServiceToken   = "{\"ExpiredTime\":\"2024-04-09T03:54:40+08:00\",\"CurrentTime\":\"2024-04-08T21:54:40+08:00\",\"AccessKeyId\":\"mock-access-key-id\",\"SecretAccessKey\":\"mock-secret-access-key\",\"SessionToken\":\"mock-session-token\"}"
)

type Client struct{}

func (m *Client) Get(ctx context.Context, sign, path string) ([]byte, error) {
	switch path {
	case "region_id":
		return []byte(RegionId), nil
	case "availability_zone":
		return []byte(AzId), nil
	case "instance_id":
		return []byte(InstanceId), nil
	case "instance_type_id":
		return []byte(InstanceTypeId), nil
	case "vpc_id":
		return []byte(VpcId), nil
	case "vpc_cidr_block":
		return []byte(VpcCidrBlock), nil
	case "network/interfaces/macs":
		return []byte(Macs), nil
	case "mac":
		return []byte(Mac), nil
	case "network/interfaces/macs/00:16:3e:15:0b:69/gateway",
		"network/interfaces/macs/00:16:3e:16:f0:f9/gateway",
		"network/interfaces/macs/00:16:3e:36:fe:9c/gateway",
		"network/interfaces/macs/00:16:3e:65:71:29/gateway":
		return []byte(GatewayIP), nil
	case "network/interfaces/macs/00:16:3e:15:0b:69/primary_ip_address",
		"network/interfaces/macs/00:16:3e:16:f0:f9/primary_ip_address",
		"network/interfaces/macs/00:16:3e:36:fe:9c/primary_ip_address",
		"network/interfaces/macs/00:16:3e:65:71:29/primary_ip_address":
		return []byte(PrimaryIP), nil
	case "network/interfaces/macs/00:16:3e:15:0b:69/network_interface_id",
		"network/interfaces/macs/00:16:3e:16:f0:f9/network_interface_id",
		"network/interfaces/macs/00:16:3e:36:fe:9c/network_interface_id",
		"network/interfaces/macs/00:16:3e:65:71:29/network_interface_id":
		return []byte(InterfaceId), nil
	case "network/interfaces/macs/00:16:3e:15:0b:69/private_ip_addresses",
		"network/interfaces/macs/00:16:3e:16:f0:f9/private_ip_addresses",
		"network/interfaces/macs/00:16:3e:36:fe:9c/private_ip_addresses",
		"network/interfaces/macs/00:16:3e:65:71:29/private_ip_addresses":
		return []byte(PrivateIps), nil
	case "network/interfaces/macs/00:16:3e:15:0b:69/network_info",
		"network/interfaces/macs/00:16:3e:16:f0:f9/network_info",
		"network/interfaces/macs/00:16:3e:36:fe:9c/network_info",
		"network/interfaces/macs/00:16:3e:65:71:29/network_info":
		return []byte(NetworkInfo), nil
	case "iam/security_credentials/" + Role:
		return []byte(ServiceToken), nil
	default:
		return nil, errors.New("not found")
	}
}

func NewMockClient() metadata.Getter {
	return &Client{}
}
