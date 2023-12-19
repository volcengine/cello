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

	t.Run("New Volc API on Volc-VKE ", func(t *testing.T) {
		accountSitePreifx := "volc:"
		helper, err := New(ec2, types.IPFamilyDual, podSubnetManager, meta, "vke", accountSitePreifx)
		assert.NoError(t, err)
		assert.NotNil(t, helper)
		assert.Equal(t, "true", helper.tags[accountSitePreifx+VkePlatformTagKey])
		assert.Equal(t, Component, helper.tags[accountSitePreifx+VkeComponentTagKey])
		assert.Equal(t, instanceId, helper.tags[accountSitePreifx+VkeInstanceIdTagKey])
	})

	t.Run("New Volc API on BytePlus-VKE ", func(t *testing.T) {
		accountSitePreifx := "sys:"
		helper, err := New(ec2, types.IPFamilyDual, podSubnetManager, meta, "vke", accountSitePreifx)
		assert.NoError(t, err)
		assert.NotNil(t, helper)
		assert.Equal(t, "true", helper.tags[accountSitePreifx+VkePlatformTagKey])
		assert.Equal(t, Component, helper.tags[accountSitePreifx+VkeComponentTagKey])
		assert.Equal(t, instanceId, helper.tags[accountSitePreifx+VkeInstanceIdTagKey])
	})

	t.Run("New Volc API on K8s", func(t *testing.T) {
		accountSitePreifx := "volc:"
		helper, err := New(ec2, types.IPFamilyDual, podSubnetManager, meta, "k8s", accountSitePreifx)
		assert.NoError(t, err)
		assert.NotNil(t, helper)
		assert.Equal(t, "", helper.tags[accountSitePreifx+VkePlatformTagKey])
		assert.Equal(t, Component, helper.tags[K8sComponentTagKey])
		assert.Equal(t, instanceId, helper.tags[K8sInstanceIdTagKey])
	})

}
