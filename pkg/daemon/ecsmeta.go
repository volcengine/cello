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

package daemon

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine"

	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
)

// getInstanceMeta is the entity to handle ECS meta info request.
type getInstanceMeta struct {
	meta helper.InstanceMetadataGetter
	api  ec2.APIGroupECS
}

func (m *getInstanceMeta) Handle(c *gin.Context) {
	api := c.Query("api")
	switch api {
	case "DescribeInstances":
		output, err := m.api.DescribeInstances(&ecs.DescribeInstancesInput{
			VpcId:       volcengine.String(m.meta.GetVpcId()),
			InstanceIds: []*string{volcengine.String(m.meta.GetInstanceId())},
		})
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.JSON(http.StatusOK, output)
	case "DescribeInstanceTypes":
		output, err := m.api.DescribeInstanceTypes(&ecs.DescribeInstanceTypesInput{
			InstanceTypes: []*string{volcengine.String(m.meta.GetInstanceType())},
		})
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.JSON(http.StatusOK, output)
	default:
		_ = c.Error(fmt.Errorf("%s not support", api))
	}
}

func newGetInstanceMetaHandler(api ec2.APIGroupECS, getter helper.InstanceMetadataGetter) Handler {
	return &getInstanceMeta{api: api, meta: getter}
}
