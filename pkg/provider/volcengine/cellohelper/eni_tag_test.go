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

	"github.com/stretchr/testify/assert"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"golang.org/x/exp/slices"
)

var tags = map[string]string{"k1": "v1", "k2": "v2"}

func TestBuildFilterForDescribeNetworkInterfacesInput(t *testing.T) {
	tagFilters := BuildFilterForDescribeNetworkInterfacesInput(tags)
	assert.NotNil(t, tagFilters)
	assert.Equal(t, 2, len(tagFilters))
	assert.True(t, slices.ContainsFunc(tagFilters, func(f *vpc.TagFilterForDescribeNetworkInterfacesInput) bool {
		return *f.Key == "k1" && *f.Values[0] == "v1"
	}))
	assert.True(t, slices.ContainsFunc(tagFilters, func(f *vpc.TagFilterForDescribeNetworkInterfacesInput) bool {
		return *f.Key == "k2" && *f.Values[0] == "v2"
	}))

}

func TestBuildTagsForCreateNetworkInterfaceInput(t *testing.T) {
	tagFilters := BuildTagsForCreateNetworkInterfaceInput(tags)
	assert.NotNil(t, tagFilters)
	assert.Equal(t, 2, len(tagFilters))
	assert.True(t, slices.ContainsFunc(tagFilters, func(f *vpc.TagForCreateNetworkInterfaceInput) bool {
		return *f.Key == "k1" && *f.Value == "v1"
	}))
	assert.True(t, slices.ContainsFunc(tagFilters, func(f *vpc.TagForCreateNetworkInterfaceInput) bool {
		return *f.Key == "k2" && *f.Value == "v2"
	}))
}
