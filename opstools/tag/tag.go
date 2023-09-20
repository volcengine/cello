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

package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/backoff"
	"github.com/volcengine/cello/pkg/metrics"
	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/credential"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
)

func createEc2(endpoint, ramRole string, instanceMeta helper.InstanceMetadataGetter) (ec2.EC2, error) {
	var credentialProvider credential.Provider
	if endpoint == "" {
		return nil, fmt.Errorf("no endpoint")
	}
	if ramRole != "" {
		log.Printf("Set credential provider by ramRole %s", ramRole)
		credentialProvider = credential.NewTSTProvider(ramRole)
	} else {
		return nil, fmt.Errorf("no credential provided")
	}

	apiClient := metrics.NewMetricEC2Wrapper(ec2.NewClient(instanceMeta.GetRegion(), endpoint, credentialProvider))
	return apiClient, nil
}

func tagEni(c *cli.Context) error {
	// instanceMetaGetter
	instanceMeta := helper.GetInstanceMetadata()

	apiClient, err := createEc2(endpoint, ramRole, instanceMeta)
	if err != nil {
		return err
	}
	volc := &volcApi{
		vpcId:      instanceMeta.GetVpcId(),
		instanceID: instanceMeta.GetInstanceId(),
		ec2Client:  apiClient,
	}
	return volc.convertENIDescriptionToTags(c)
}

func listTaggedEni(c *cli.Context) error {
	// instanceMetaGetter
	instanceMeta := helper.GetInstanceMetadata()

	apiClient, err := createEc2(endpoint, ramRole, instanceMeta)
	if err != nil {
		return err
	}
	volc := &volcApi{
		vpcId:      instanceMeta.GetVpcId(),
		instanceID: instanceMeta.GetInstanceId(),
		ec2Client:  apiClient,
	}

	enis, err := volc.getNetworkInterfacesCreatedByCelloWithTag(c)
	if err != nil {
		return err
	}
	printEni(enis)
	return nil
}

type volcApi struct {
	vpcId      string
	instanceID string
	ec2Client  ec2.EC2
}

func (v *volcApi) convertENIDescriptionToTags(c *cli.Context) error {
	enis, err := v.getNetworkInterfacesCreatedByCelloWithoutTag(c)
	if err != nil {
		log.Printf("Get enis created by cello(have special description, no tags) on instance %s failed, %v",
			v.instanceID, err)
		return err
	}
	log.Printf("%d eni waiting to tag:\n", len(enis))
	printEni(enis)
	log.Println()
	if c.Bool("exec") {
		return v.tagENIs(enis)
	}
	return nil
}

func (v *volcApi) tagENIs(enis []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput) error {
	if len(enis) == 0 {
		return nil
	}
	var err error

	var eniTags []*vpc.TagForTagResourcesInput
	tagStr := func(eniTags []*vpc.TagForTagResourcesInput) string {
		var strs []string
		for _, tag := range eniTags {
			strs = append(strs, fmt.Sprintf("%s=%s", volcengine.StringValue(tag.Key), volcengine.StringValue(tag.Value)))
		}
		return fmt.Sprintf("%v", strs)
	}
	for _, eni := range enis {
		// tag
		expectDescriptionPrefix := fmt.Sprintf("%s.%s %s.%s %s.", TagComponentKey, ComponentName, TagVpcIdKey, v.vpcId, TagInstanceKey)
		eniInstance, found := strings.CutPrefix(volcengine.StringValue(eni.Description), expectDescriptionPrefix)
		if !found || !strings.HasPrefix(eniInstance, "i-") {
			log.Printf("eni %s description not expected: %s", volcengine.StringValue(eni.NetworkInterfaceId), volcengine.StringValue(eni.Description))
			continue
		}
		log.Printf("%s tagging", volcengine.StringValue(eni.NetworkInterfaceId))
		werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIWriteOps), func() (bool, error) {
			eniTags = buildSDKTagForTagResourcesInput(eniInstance)
			_, err = v.ec2Client.TagResources(&vpc.TagResourcesInput{
				ResourceIds:  []*string{eni.NetworkInterfaceId},
				ResourceType: volcengine.String(vpc.ResourceTypeForTagResourcesInputEni),
				Tags:         eniTags,
			})
			return err == nil, err
		})
		if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
			log.Printf("Add Tag for eni %s failed, %v", volcengine.StringValue(eni.NetworkInterfaceId), err)
			return err
		}
		log.Printf("%s tagged: %s", volcengine.StringValue(eni.NetworkInterfaceId), tagStr(eniTags))
	}

	return nil
}

const maxPageSize = 100

type TagFilterForDescribeNetworkInterfacesInput []*vpc.TagFilterForDescribeNetworkInterfacesInput
type FilterForDescribeNetworkInterfacesOutput func([]*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput) []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput

func (v *volcApi) describeNetworkInterfacesWithPage(pageNumber int, status string, eniType string, eniIDs []string, inputFilter TagFilterForDescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error) {
	var resp *ec2.DescribeNetworkInterfacesOutput
	var err error
	input := &vpc.DescribeNetworkInterfacesInput{
		Type:                volcengine.String(eniType),
		VpcId:               volcengine.String(v.vpcId),
		NetworkInterfaceIds: volcengine.StringSlice(eniIDs),
		PageNumber:          volcengine.Int64(int64(pageNumber)),
		PageSize:            volcengine.Int64(maxPageSize),
	}
	if status != "" {
		input.Status = volcengine.String(status)
	}
	if status == helper.ENIStatusInuse {
		input.InstanceId = volcengine.String(v.instanceID)
	}

	if inputFilter != nil {
		input.TagFilters = inputFilter
	}

	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		resp, err = v.ec2Client.DescribeNetworkInterfaces(input)
		return err == nil, nil
	})
	return resp, apiErr.BackoffErrWrapper(werr, err)
}

func (v *volcApi) getNetworkInterfacesByDescribe(status string, eniType string, eniIDs []string, inputFilter TagFilterForDescribeNetworkInterfacesInput,
	outputFilter FilterForDescribeNetworkInterfacesOutput) (int, []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	var preResult []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput
	var result []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput
	pages := 1
	first := true
	for i := 1; i <= pages; i++ {
		resp, err := v.describeNetworkInterfacesWithPage(i, status, eniType, eniIDs, inputFilter)
		if err != nil {
			log.Printf("describeNetworkInterfacesWithPage failed: %s", err.Error())
			return 0, result, err
		}

		total := int(volcengine.Int64Value(resp.TotalCount))
		if total == 0 {
			return 0, result, nil
		}
		preResult = append(preResult, resp.NetworkInterfaceSets...)
		if first {
			pages = total / maxPageSize
			if total%maxPageSize != 0 {
				pages += 1
			}
			first = false
		}
	}
	if outputFilter != nil {
		return len(preResult), outputFilter(preResult), nil
	}
	return len(preResult), preResult, nil
}

func (v *volcApi) getNetworkInterfacesCreatedByCelloWithoutTag(c *cli.Context) ([]*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	expectDescriptionPrefix := fmt.Sprintf("%s.%s %s.%s %s.%s", TagComponentKey, ComponentName, TagVpcIdKey, v.vpcId, TagInstanceKey, v.instanceID)
	if c.Bool("vpc-all") {
		expectDescriptionPrefix = fmt.Sprintf("%s.%s %s.%s %s.", TagComponentKey, ComponentName, TagVpcIdKey, v.vpcId, TagInstanceKey)
	}

	filterNetworkInterfacesWithDescriptionWithoutTags := func(ifaces []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput) []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput {
		var result []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput
		for _, ifa := range ifaces {
			// with special description
			if strings.HasPrefix(volcengine.StringValue(ifa.Description), expectDescriptionPrefix) &&
				// without tags
				!existSDKTagForDescribeNetworkInterfacesOutput(ifa.Tags) {
				result = append(result, ifa)
			}
		}
		return result
	}
	_, enis, err := v.getNetworkInterfacesByDescribe("", helper.ENITypeSecondary, nil, nil, filterNetworkInterfacesWithDescriptionWithoutTags)
	return enis, err
}

func (v *volcApi) getNetworkInterfacesCreatedByCelloWithTag(c *cli.Context) ([]*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	instanceId := v.instanceID
	if c.Bool("vpc-all") {
		instanceId = ""
	}

	_, enis, err := v.getNetworkInterfacesByDescribe("", helper.ENITypeSecondary, nil, buildSDKTagFilterForDescribeNetworkInterfacesInput(instanceId), nil)
	return enis, err
}

const (
	TagVpcIdKey     = "vpcId"
	TagInstanceKey  = "instanceId"
	TagComponentKey = "createdBy"
	ComponentName   = "Cello"
)

const (
	TagPrefix           = "volc:vke:"
	VkePlatformTagKey   = TagPrefix + "createdby-vke-flag"
	VkePlatformTagValue = "true"
	ComponentTagKey     = TagPrefix + "created-by"
	InstanceIdTagKey    = TagPrefix + "ecs-id"
	Component           = "cello"
	eniDescription      = "interface create by cello"
)

func buildSDKTagForTagResourcesInput(instanceId string) []*vpc.TagForTagResourcesInput {
	return []*vpc.TagForTagResourcesInput{
		{Key: volcengine.String(VkePlatformTagKey), Value: volcengine.String(VkePlatformTagValue)},
		{Key: volcengine.String(ComponentTagKey), Value: volcengine.String(Component)},
		{Key: volcengine.String(InstanceIdTagKey), Value: volcengine.String(instanceId)},
	}
}

func buildSDKTagFilterForDescribeNetworkInterfacesInput(instanceId string) []*vpc.TagFilterForDescribeNetworkInterfacesInput {
	tags := []*vpc.TagFilterForDescribeNetworkInterfacesInput{
		{Key: volcengine.String(VkePlatformTagKey), Values: []*string{volcengine.String(VkePlatformTagValue)}},
		{Key: volcengine.String(ComponentTagKey), Values: []*string{volcengine.String(Component)}},
	}
	if instanceId != "" {
		instanceTag := &vpc.TagFilterForDescribeNetworkInterfacesInput{Key: volcengine.String(InstanceIdTagKey), Values: []*string{volcengine.String(instanceId)}}
		tags = append(tags, instanceTag)
	}
	return tags
}

func existSDKTagForDescribeNetworkInterfacesOutput(tags []*vpc.TagForDescribeNetworkInterfacesOutput) bool {
	hit := 0
	for _, tag := range tags {
		if *tag.Key == VkePlatformTagKey && *tag.Value == VkePlatformTagValue {
			hit += 1
		}
		if *tag.Key == ComponentTagKey && *tag.Value == Component {
			hit += 1
		}
	}
	return hit == 2
}

func printEni(enis []*ec2.NetworkInterfaceSetForDescribeNetworkInterfacesOutput) {
	for id, eni := range enis {
		var tagStr []string
		for _, tag := range eni.Tags {
			tagStr = append(tagStr, fmt.Sprintf("%s=%s", volcengine.StringValue(tag.Key), volcengine.StringValue(tag.Value)))
		}
		log.Printf("{%d: id: %s, description: %s, tags: %v}\n",
			id, volcengine.StringValue(eni.NetworkInterfaceId), volcengine.StringValue(eni.Description), tagStr)
	}
}
