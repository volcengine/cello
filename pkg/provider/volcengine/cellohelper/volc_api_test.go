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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"golang.org/x/time/rate"

	"github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/mock"
	ec2Mock "github.com/volcengine/cello/pkg/provider/volcengine/ec2/mock"
	trMock "github.com/volcengine/cello/pkg/tracing/mock"
	"github.com/volcengine/cello/types"
)

func Test_New(t *testing.T) {
	const (
		VpcId  = "vpc-test123"
		ZoneId = "cn-beijing-a"
	)
	ctrl := gomock.NewController(t)
	ec2 := ec2Mock.NewMockEC2(ctrl)
	meta := mock.NewMockInstanceMetadataGetter(ctrl)
	podSubnetManager, err := NewPodSubnetManager(ZoneId, VpcId, ec2,
		WithEventRecord(trMock.NewFakeTracker()), WithEventLimiter(rate.NewLimiter(20, 20)))
	assert.NoError(t, err)
	instanceId := "i-y1234566787"
	meta.EXPECT().GetInstanceId().AnyTimes().Return(instanceId)

	t.Run("New Volc API on Volcengine-VKE ", func(t *testing.T) {
		helper, err := New(ec2, types.IPFamilyDual, podSubnetManager, meta,
			[]string{"volc:vke:", "sys:vke:"}, map[string]string{"volc:vke:createdby-vke-flag": "true"})
		assert.NoError(t, err)
		assert.NotNil(t, helper)
		assert.Equal(t, "true", helper.tags["volc:vke:createdby-vke-flag"])
		assert.Equal(t, ComponentTagValue, helper.tags["volc:vke:"+ComponentTagKey])
		assert.Equal(t, instanceId, helper.tags["volc:vke:"+InstanceIDTagKey])
	})

	t.Run("New Volc API on BytePlus-VKE ", func(t *testing.T) {
		helper, err := New(ec2, types.IPFamilyDual, podSubnetManager, meta,
			[]string{"sys:vke:", "volc:vke:"}, map[string]string{"sys:vke:createdby-vke-flag": "true"})
		assert.NoError(t, err)
		assert.NotNil(t, helper)
		assert.Equal(t, "true", helper.tags["sys:vke:createdby-vke-flag"])
		assert.Equal(t, ComponentTagValue, helper.tags["sys:vke:"+ComponentTagKey])
		assert.Equal(t, instanceId, helper.tags["sys:vke:"+InstanceIDTagKey])
	})

}

func Test_managedByCello(t *testing.T) {
	instanceId := "i-y1234566787"
	eniTagsWithVolcPrefix := []*vpc.TagForDescribeNetworkInterfacesOutput{
		{
			Key:   volcengine.String("volc:vke:createdby-vke-flag"),
			Value: volcengine.String("true"),
		},
		{
			Key:   volcengine.String("volc:vke:" + ComponentTagKey),
			Value: volcengine.String(ComponentTagValue),
		},
		{
			Key:   volcengine.String("volc:vke:" + InstanceIDTagKey),
			Value: volcengine.String(instanceId),
		},
	}
	eniTagsWithSysPrefix := []*vpc.TagForDescribeNetworkInterfacesOutput{
		{
			Key:   volcengine.String("sys:vke:createdby-vke-flag"),
			Value: volcengine.String("true"),
		},
		{
			Key:   volcengine.String("sys:vke:" + ComponentTagKey),
			Value: volcengine.String(ComponentTagValue),
		},
		{
			Key:   volcengine.String("sys:vke:" + InstanceIDTagKey),
			Value: volcengine.String(instanceId),
		},
	}

	assert.True(t, isENIManagedByCello(eniTagsWithVolcPrefix, []string{"sys:vke:" + ComponentTagKey, "volc:vke:" + ComponentTagKey}))
	assert.True(t, isENIManagedByCello(eniTagsWithSysPrefix, []string{"sys:vke:" + ComponentTagKey, "volc:vke:" + ComponentTagKey}))
	assert.False(t, isENIManagedByCello(eniTagsWithVolcPrefix, []string{"sys:vke:" + ComponentTagKey}))
	assert.False(t, isENIManagedByCello(eniTagsWithSysPrefix, []string{"volc:vke:" + ComponentTagKey}))
	assert.False(t, isENIManagedByCello([]*vpc.TagForDescribeNetworkInterfacesOutput{}, []string{"sys:vke:" + ComponentTagKey, "volc:vke:" + ComponentTagKey}))
}
