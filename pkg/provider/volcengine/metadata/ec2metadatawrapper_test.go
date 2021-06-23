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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	mockmetadata "github.com/volcengine/cello/pkg/provider/volcengine/metadata/mock"
)

const (
	az     = "cn-beijing-a"
	eniMac = "82:94:32:47:34:01"
	eniId  = "eni-test123"
)

var (
	mockMetadataIface *mockmetadata.MockEC2MetadataIface
	testClient        *EC2MetadataWrapper
	ctx               context.Context
)

func setup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockMetadataIface = mockmetadata.NewMockEC2MetadataIface(ctrl)
	testClient = &EC2MetadataWrapper{mockMetadataIface}
	ctx = context.TODO()
}

func TestEC2MetadataWrapper_GetAvailabilityZone(t *testing.T) {
	setup(t)

	mockMetadataIface.EXPECT().GetMetadata(gomock.Any(), gomock.Eq(azPath)).Return(az, nil)
	azG, err := testClient.GetAvailabilityZone(ctx)
	assert.NoError(t, err)
	assert.Equal(t, az, azG)
}

func TestEC2MetadataWrapper_GetENIID(t *testing.T) {
	setup(t)

	mockMetadataIface.EXPECT().GetMetadata(gomock.Any(), gomock.Eq(fmt.Sprintf(eniIDPath, eniMac))).Return(eniId, nil)
	eniIdG, err := testClient.GetENIID(ctx, eniMac)
	assert.NoError(t, err)
	assert.Equal(t, eniId, eniIdG)
}
