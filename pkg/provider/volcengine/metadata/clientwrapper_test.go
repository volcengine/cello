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

package metadata_test

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/strings/slices"

	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
	"github.com/volcengine/cello/pkg/provider/volcengine/metadata/mock"
)

var ctx = context.Background()
var meta = metadata.NewClientWrapper(mock.NewMockClient())

func TestClientWrapper(t *testing.T) {
	meta := metadata.NewClientWrapper(metadata.NewClient())
	assert.NotNil(t, meta)
}
func TestClientWrapper_AvailabilityZone(t *testing.T) {
	az, err := meta.AvailabilityZone(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.AzId, az)
}

func TestClientWrapper_GatewayIP(t *testing.T) {
	ip, err := meta.InterfaceGatewayIP(ctx, mock.Mac)
	assert.NoError(t, err)
	assert.True(t, ip.Equal(net.ParseIP(mock.GatewayIP)))

	_, err = meta.InterfaceGatewayIP(ctx, "")
	assert.Error(t, err)
}

func TestClientWrapper_InstanceID(t *testing.T) {
	id, err := meta.InstanceID(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.InstanceId, id)
}

func TestClientWrapper_InstanceType(t *testing.T) {
	instanceType, err := meta.InstanceType(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.InstanceTypeId, instanceType)
}

func TestClientWrapper_InterfaceMacAddresses(t *testing.T) {
	macs, err := meta.MacAddresses(ctx)
	assert.NoError(t, err)
	res := strings.Split(mock.Macs, "\n")
	for _, mac := range res {
		assert.True(t, slices.Contains(macs, mac))
	}
}

func TestClientWrapper_PrimaryInterfaceMacAddress(t *testing.T) {
	mac, err := meta.PrimaryMacAddress(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.Mac, mac)
}

func TestClientWrapper_Region(t *testing.T) {
	region, err := meta.Region(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.RegionId, region)
}

func TestClientWrapper_VPCCidrBlock(t *testing.T) {
	cidr, err := meta.VPCCidrBlock(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.VpcCidrBlock, cidr)
}

func TestClientWrapper_VPCID(t *testing.T) {
	id, err := meta.VPCID(ctx)
	assert.NoError(t, err)
	assert.Equal(t, mock.VpcId, id)
}

func TestClientWrapper_InterfaceInfo(t *testing.T) {
	info, err := meta.InterfaceInfo(ctx, mock.Mac)
	assert.NoError(t, err)
	if assert.NotNil(t, info) {
		assert.Equal(t, mock.GatewayIP, info.Gateway)
		assert.Equal(t, mock.InterfaceId, info.NetworkInterfaceID)
		assert.Equal(t, mock.PrimaryIP, info.PrimaryIPAddress)
		assert.Equal(t, mock.SubnetId, info.SubnetID)
		assert.Equal(t, mock.SubnetCidr, info.SubnetCidrBlock)
		assert.NotZero(t, len(info.PrivateIPAddresses))
	}

	_, err = meta.InterfaceInfo(ctx, "")
	assert.Error(t, err)
}

func TestClientWrapper_InterfaceInfoWithEmptyAddresses(t *testing.T) {
	info, err := meta.InterfaceInfo(ctx, mock.AnotherMac)
	assert.NoError(t, err)
	if assert.NotNil(t, info) {
		assert.Equal(t, mock.GatewayIP, info.Gateway)
		assert.Equal(t, mock.InterfaceId, info.NetworkInterfaceID)
		assert.Equal(t, mock.PrimaryIP, info.PrimaryIPAddress)
		assert.Equal(t, mock.SubnetId, info.SubnetID)
		assert.Equal(t, mock.SubnetCidr, info.SubnetCidrBlock)
		assert.Empty(t, info.PrivateIPAddresses)
	}

	_, err = meta.InterfaceInfo(ctx, "")
	assert.Error(t, err)
}

func TestClientWrapper_InterfaceID(t *testing.T) {
	id, err := meta.InterfaceID(ctx, mock.Mac)
	assert.NoError(t, err)
	assert.Equal(t, mock.InterfaceId, id)
}

func TestClientWrapper_PrimaryIP(t *testing.T) {
	ip, err := meta.InterfacePrimaryIP(ctx, mock.Mac)
	assert.NoError(t, err)
	assert.True(t, ip.Equal(net.ParseIP(mock.PrimaryIP)))
}

func TestClientWrapper_IPAddresses(t *testing.T) {
	ips, err := meta.InterfaceSecondaryIPs(ctx, mock.Mac)
	assert.NoError(t, err)
	res := strings.Split(mock.PrivateIps, "\n")
	assert.Equal(t, len(res), len(ips))
}

func TestClientWrapper_EmptyAddresses(t *testing.T) {
	ips, err := meta.InterfaceSecondaryIPs(ctx, mock.AnotherMac)
	assert.NoError(t, err)
	assert.Empty(t, ips)
}

func TestClientWrapper_STS(t *testing.T) {
	token, err := meta.STSCredential(ctx, mock.Role)
	assert.NoError(t, err)
	assert.NotZero(t, len(token))

	_, err = meta.STSCredential(ctx, "")
	assert.Error(t, err)

	_, err = meta.STSCredential(ctx, "NotExists")
	assert.Error(t, err)
}

func TestClientWrapper_NetworkData(t *testing.T) {
	networkData, err := meta.NetworkData(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(networkData.Links), 5)

	var storageRdmaCnt int
	for _, link := range networkData.Links {
		if link.ExtraData != nil {
			assert.Equal(t, link.ExtraData.RdmaDataType, metadata.RdmaDataTypeStorage)
			storageRdmaCnt++
		}
	}
	assert.Equal(t, storageRdmaCnt, 4)

	mock.VarNetworkData = "{\"services\":[],\"networks\":[{\"id\":\"\",\"services\":[],\"ip_address\":\"\",\"type\":\"ipv4_dhcp\",\"network_id\":\"\",\"routes\":[],\"netmask\":\"\",\"link\":\"network_0\"},{\"id\":\"\",\"services\":[],\"ip_address\":\"\",\"type\":\"ipv4_dhcp\",\"network_id\":\"\",\"routes\":[],\"netmask\":\"\",\"link\":\"network_1\"},{\"id\":\"\",\"services\":[],\"ip_address\":\"\",\"type\":\"ipv4_dhcp\",\"network_id\":\"\",\"routes\":[],\"netmask\":\"\",\"link\":\"network_2\"},{\"id\":\"\",\"services\":[],\"ip_address\":\"\",\"type\":\"ipv4_dhcp\",\"network_id\":\"\",\"routes\":[],\"netmask\":\"\",\"link\":\"network_3\"},{\"id\":\"\",\"services\":[],\"ip_address\":\"\",\"type\":\"ipv4_dhcp\",\"network_id\":\"\",\"routes\":[],\"netmask\":\"\",\"link\":\"network_4\"}],\"links\":[{\"id\":\"network_0\",\"ethernet_mac_address\":\"00:16:3e:49:85:0c\",\"type\":\"bridge\",\"mtu\":0,\"vif_id\":\"\",\"extra_data\":\"\"},{\"id\":\"network_1\",\"ethernet_mac_address\":\"94:6d:ae:6e:0c:18\",\"type\":\"bridge\",\"mtu\":0,\"vif_id\":\"\",\"extra_data\":\"{\\\"RdmaDataType\\\":\\\"Storage\\\"}\"},{\"id\":\"network_2\",\"ethernet_mac_address\":\"94:6d:ae:5c:36:a8\",\"type\":\"bridge\",\"mtu\":0,\"vif_id\":\"\",\"extra_data\":\"{\\\"RdmaDataType\\\":\\\"Storage\\\"}\"},{\"id\":\"network_3\",\"ethernet_mac_address\":\"94:6d:ae:5c:35:f8\",\"type\":\"bridge\",\"mtu\":0,\"vif_id\":\"\",\"extra_data\":\"{\\\"RdmaDataType\\\":\\\"Storage\\\"}\"},{\"id\":\"network_4\",\"ethernet_mac_address\":\"94:6d:ae:5c:36:04\",\"type\":\"bridge\",\"mtu\":0,\"vif_id\":\"\",\"extra_data\":\"{\"RdmaDataType\":\"Storage\"}\"}]}"
	networkData, err = meta.NetworkData(ctx)
	assert.Error(t, err)

	mock.VarNetworkData = "404"
	networkData, err = meta.NetworkData(ctx)
	assert.Error(t, err)
}
