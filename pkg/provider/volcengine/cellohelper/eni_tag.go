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
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
)

const (
	VkeTagPrefix        = "volc:vke:"
	VkePlatformTagKey   = VkeTagPrefix + "createdby-vke-flag"
	VkePlatformTagValue = "true"
	VkeComponentTagKey  = VkeTagPrefix + "created-by"
	VkeInstanceIdTagKey = VkeTagPrefix + "ecs-id"

	K8sTagPrefix        = "k8s:cello:"
	K8sComponentTagKey  = K8sTagPrefix + "created-by"
	K8sInstanceIdTagKey = K8sTagPrefix + "ecs-id"

	Component      = "cello"
	eniDescription = "interface create by cello"
)

func BuildTagsForCreateNetworkInterfaceInput(tags map[string]string) []*vpc.TagForCreateNetworkInterfaceInput {
	var tagsInput []*vpc.TagForCreateNetworkInterfaceInput
	for k, v := range tags {
		tagsInput = append(tagsInput, &vpc.TagForCreateNetworkInterfaceInput{
			Key:   volcengine.String(k),
			Value: volcengine.String(v),
		})
	}
	return tagsInput
}

func BuildFilterForDescribeNetworkInterfacesInput(tags map[string]string) []*vpc.TagFilterForDescribeNetworkInterfacesInput {
	var tagsInput []*vpc.TagFilterForDescribeNetworkInterfacesInput
	for k, v := range tags {
		tagsInput = append(tagsInput, &vpc.TagFilterForDescribeNetworkInterfacesInput{
			Key:    volcengine.String(k),
			Values: volcengine.StringSlice([]string{v}),
		})
	}
	return tagsInput
}
