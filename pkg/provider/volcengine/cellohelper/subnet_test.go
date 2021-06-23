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

package cellohelper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"

	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"

	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
	ec2Mock "github.com/volcengine/cello/pkg/provider/volcengine/ec2/mock"
	trMock "github.com/volcengine/cello/pkg/tracing/mock"
	"github.com/volcengine/cello/types"
)

const (
	AccountId       = "accountId-123"
	CreationTime    = "2022-02-15T17:36:13+08:00"
	UpdateTime      = "2022-02-15T17:36:13+08:00"
	ProjectName     = "default"
	StatusAvailable = "Available"
	VpcId           = "vpc-test123"
	ZoneId          = "cn-beijing-a"
	ZoneId2         = "cn-beijing-b"
)

var (
	subnets                                               map[string]*ec2.SubnetForDescribeSubnetsOutput
	ctrl                                                  *gomock.Controller
	apiClient                                             ec2.APIGroupSubnet
	subnetId1, subnetId2, subnetId3, subnetId4, subnetId5 string
)

func setup(t *testing.T) {
	ctrl = gomock.NewController(t)
	mockClient := ec2Mock.NewMockEC2(ctrl)
	apiClient = mockClient

	subnets = map[string]*ec2.SubnetForDescribeSubnetsOutput{}
	subnetId1 = "subnet-1"
	subnets[subnetId1] = &ec2.SubnetForDescribeSubnetsOutput{
		AccountId:               volcengine.String(AccountId),
		AvailableIpAddressCount: volcengine.Int64(240),
		CidrBlock:               volcengine.String("192.168.1.0/24"),
		CreationTime:            volcengine.String(CreationTime),
		ProjectName:             volcengine.String(ProjectName),
		Status:                  volcengine.String(StatusAvailable),
		SubnetId:                volcengine.String(subnetId1),
		SubnetName:              volcengine.String(subnetId1),
		TotalIpv4Count:          volcengine.Int64(255),
		UpdateTime:              volcengine.String(UpdateTime),
		VpcId:                   volcengine.String(VpcId),
		ZoneId:                  volcengine.String(ZoneId),
	}
	subnetId2 = "subnet-2"
	subnets[subnetId2] = &ec2.SubnetForDescribeSubnetsOutput{
		AccountId:               volcengine.String(AccountId),
		AvailableIpAddressCount: volcengine.Int64(32),
		CidrBlock:               volcengine.String("192.168.2.0/24"),
		CreationTime:            volcengine.String(CreationTime),
		ProjectName:             volcengine.String(ProjectName),
		Status:                  volcengine.String(StatusAvailable),
		SubnetId:                volcengine.String(subnetId2),
		SubnetName:              volcengine.String(subnetId2),
		TotalIpv4Count:          volcengine.Int64(255),
		UpdateTime:              volcengine.String(UpdateTime),
		VpcId:                   volcengine.String(VpcId),
		ZoneId:                  volcengine.String(ZoneId),
	}

	subnetId3 = "subnet-3"
	subnets[subnetId3] = &ec2.SubnetForDescribeSubnetsOutput{
		AccountId:               volcengine.String(AccountId),
		AvailableIpAddressCount: volcengine.Int64(0),
		CidrBlock:               volcengine.String("192.168.3.0/24"),
		CreationTime:            volcengine.String(CreationTime),
		ProjectName:             volcengine.String(ProjectName),
		Status:                  volcengine.String(StatusAvailable),
		SubnetId:                volcengine.String(subnetId3),
		SubnetName:              volcengine.String(subnetId3),
		TotalIpv4Count:          volcengine.Int64(255),
		UpdateTime:              volcengine.String(UpdateTime),
		VpcId:                   volcengine.String(VpcId),
		ZoneId:                  volcengine.String(ZoneId),
	}

	subnetId4 = "subnet-4"
	subnets[subnetId4] = &ec2.SubnetForDescribeSubnetsOutput{
		AccountId:               volcengine.String(AccountId),
		AvailableIpAddressCount: volcengine.Int64(251),
		CidrBlock:               volcengine.String("192.168.4.0/24"),
		CreationTime:            volcengine.String(CreationTime),
		ProjectName:             volcengine.String(ProjectName),
		Status:                  volcengine.String(StatusAvailable),
		SubnetId:                volcengine.String(subnetId4),
		SubnetName:              volcengine.String(subnetId4),
		TotalIpv4Count:          volcengine.Int64(255),
		UpdateTime:              volcengine.String(UpdateTime),
		VpcId:                   volcengine.String(VpcId),
		ZoneId:                  volcengine.String(ZoneId2),
	}

	subnetId5 = "subnet-5"
	subnets[subnetId5] = &ec2.SubnetForDescribeSubnetsOutput{
		AccountId:               volcengine.String(AccountId),
		AvailableIpAddressCount: volcengine.Int64(27),
		CidrBlock:               volcengine.String("192.168.5.0/24"),
		CreationTime:            volcengine.String(CreationTime),
		ProjectName:             volcengine.String(ProjectName),
		Status:                  volcengine.String(StatusAvailable),
		SubnetId:                volcengine.String(subnetId5),
		SubnetName:              volcengine.String(subnetId5),
		TotalIpv4Count:          volcengine.Int64(255),
		UpdateTime:              volcengine.String(UpdateTime),
		VpcId:                   volcengine.String(VpcId),
		ZoneId:                  volcengine.String(ZoneId),
	}

	mockClient.EXPECT().DescribeSubnets(gomock.Any()).DoAndReturn(func(input *vpc.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
		var result []*ec2.SubnetForDescribeSubnetsOutput
		for _, id := range input.SubnetIds {
			if item, exist := subnets[*id]; exist {
				result = append(result, item)
			}
		}
		metadata := &response.ResponseMetadata{
			RequestId: "Mock_DescribeSubnets_EEFF",
			Action:    "DescribeSubnets",
			Version:   "2022-04-01",
			Service:   "vpc",
			Region:    "cn-a",
			HTTPCode:  http.StatusOK,
			Error:     nil,
		}
		return &ec2.DescribeSubnetsOutput{
			Metadata:   metadata,
			PageNumber: volcengine.Int64(1),
			PageSize:   volcengine.Int64(100),
			RequestId:  volcengine.String("Mock_EEFF"),
			Subnets:    result,
			TotalCount: volcengine.Int64(int64(len(result))),
		}, nil
	}).AnyTimes()

	mockClient.EXPECT().DescribeSubnetAttributes(gomock.Any()).DoAndReturn(func(input *vpc.DescribeSubnetAttributesInput) (*ec2.DescribeSubnetAttributesOutput, error) {
		metadata := &response.ResponseMetadata{
			RequestId: "Mock_DescribeSubnetAttributes_EEFF",
			Action:    "DescribeSubnetAttributes",
			Version:   "2022-04-01",
			Service:   "vpc",
			Region:    "cn-a",
			HTTPCode:  http.StatusOK,
			Error:     nil,
		}

		subnet, exist := subnets[volcengine.StringValue(input.SubnetId)]
		if !exist {
			metadata.HTTPCode = http.StatusNotFound
			metadata.Error = &response.Error{
				CodeN:   0,
				Code:    apiErr.InvalidSubnetNotFound,
				Message: fmt.Sprintf("subnet %s not found", volcengine.StringValue(input.SubnetId)),
			}
			return &ec2.DescribeSubnetAttributesOutput{
				Metadata: metadata,
			}, apiErr.NewAPIRequestErr(metadata, nil)
		}

		return &ec2.DescribeSubnetAttributesOutput{
			Metadata:                metadata,
			AccountId:               subnet.AccountId,
			AvailableIpAddressCount: subnet.AvailableIpAddressCount,
			CidrBlock:               subnet.CidrBlock,
			CreationTime:            subnet.CreationTime,
			Description:             subnet.Description,
			Ipv6CidrBlock:           subnet.Ipv6CidrBlock,
			NetworkAclId:            subnet.NetworkAclId,
			ProjectName:             subnet.ProjectName,
			RequestId:               volcengine.String(metadata.RequestId),
			Status:                  subnet.Status,
			SubnetId:                subnet.SubnetId,
			SubnetName:              subnet.SubnetName,
			TotalIpv4Count:          subnet.TotalIpv4Count,
			UpdateTime:              subnet.UpdateTime,
			VpcId:                   subnet.VpcId,
			ZoneId:                  subnet.ZoneId,
		}, nil
	}).AnyTimes()
}

func clean() {
	ctrl.Finish()
}

func TestPodSubnetManager(t *testing.T) {
	setup(t)
	defer clean()

	// test new
	podSubnetManager, err := NewPodSubnetManager(ZoneId, VpcId, apiClient,
		WithEventRecord(trMock.NewFakeTracker()), WithEventLimiter(rate.NewLimiter(20, 20)))
	assert.NoError(t, err)

	// test init flush
	err = podSubnetManager.FlushSubnets([]string{subnetId1, subnetId2, subnetId3, subnetId4}...)
	assert.NoError(t, err)

	status := podSubnetManager.Status()
	assert.Equal(t, 3, len(status.PodSubnets))
	assert.Equal(t, 0, len(status.LegacyPodSubnets))

	statusStr, _ := json.MarshalIndent(status, " ", "\t")
	t.Logf("podSubnets status: %s\n", statusStr)

	// test select subnet
	selectedSubnet := podSubnetManager.SelectSubnet(types.IPFamilyIPv4)
	assert.Equal(t, subnetId1, selectedSubnet.SubnetId)

	// subnet info change
	subnets[subnetId1].AvailableIpAddressCount = volcengine.Int64(100)
	subnets[subnetId5].AvailableIpAddressCount = volcengine.Int64(25)

	// test update status
	err = podSubnetManager.UpdateSubnetsStatus()
	assert.NoError(t, err)
	status = podSubnetManager.Status()
	assert.Equal(t, 100, status.PodSubnets[subnetId1].GetAvailableIpAddressCount())
	assert.Equal(t, 3, len(status.PodSubnets))
	assert.Equal(t, 0, len(status.LegacyPodSubnets))

	subnets[subnetId2].AvailableIpAddressCount = volcengine.Int64(101)

	selectedSubnet = podSubnetManager.SelectSubnet(types.IPFamilyIPv4)
	assert.Equal(t, subnetId2, selectedSubnet.SubnetId)

	// test GetUpdatedPodSubnet
	subnets[subnetId2].AvailableIpAddressCount = volcengine.Int64(20)
	subnet, err := podSubnetManager.GetUpdatedPodSubnet(subnetId2)
	assert.NoError(t, err)
	subnetStr, _ := json.MarshalIndent(subnet, " ", "\t")
	t.Logf("Subnet: %s\n", subnetStr)

	// test GetUpdatedPodSubnet not exist
	subnet, err = podSubnetManager.GetUpdatedPodSubnet(subnetId5)
	assert.NoError(t, err)
	assert.Equal(t, subnetId5, subnet.SubnetId)
	status = podSubnetManager.Status()
	assert.Equal(t, 3, len(status.PodSubnets))
	assert.Equal(t, 1, len(status.LegacyPodSubnets))
	statusStr, _ = json.MarshalIndent(status, " ", "\t")
	t.Logf("podSubnets status: %s\n", statusStr)

	// test disable subnet
	podSubnetManager.DisableSubnet(subnetId2)
	selectedSubnet = podSubnetManager.SelectSubnet(types.IPFamilyIPv4)
	assert.Equal(t, subnetId1, selectedSubnet.SubnetId)

	selectedSubnet = podSubnetManager.SelectSubnet(types.IPFamilyDual)
	assert.Equal(t, (*PodSubnet)(nil), selectedSubnet)
}
