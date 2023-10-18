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

package ec2

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	"github.com/volcengine/volcengine-go-sdk/volcengine/universal"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineutil"

	"github.com/volcengine/cello/pkg/metrics"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/credential"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/version"
)

type ClientSet struct {
	VpcSvc    *vpc.VPC
	EcsSvc    *ecs.ECS
	universal *universal.Universal
}

func (c *ClientSet) DescribeInstances(input *ecs.DescribeInstancesInput) (*ecs.DescribeInstancesOutput, error) {
	var output *ecs.DescribeInstancesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeInstances", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeInstances", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeInstances"})
		}
	}()
	output, err = c.EcsSvc.DescribeInstancesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DescribeInstanceTypes(input *ecs.DescribeInstanceTypesInput) (*DescribeInstanceTypesOutput, error) {
	var output *DescribeInstanceTypesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeInstanceTypes", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeInstanceTypes", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeInstanceTypes"})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeInstanceTypes",
		Version:     "2020-04-01",
		ServiceName: "ecs",
		HttpMethod:  universal.GET,
	}
	output = &DescribeInstanceTypesOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) CreateNetworkInterface(input *CreateNetworkInterfaceInput) (*vpc.CreateNetworkInterfaceOutput, error) {
	var output *vpc.CreateNetworkInterfaceOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("CreateNetworkInterface", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("CreateNetworkInterface", err)
			apiErr.RecordOpenAPIErrEvent(err,
				apiErr.EventInfoField{Key: "API", Value: "CreateNetworkInterface"},
				apiErr.EventInfoField{Key: "SubnetId", Value: volcengine.StringValue(input.SubnetId)},
				apiErr.EventInfoField{Key: "SecurityGroupIds", Value: volcengine.StringValueSlice(input.SecurityGroupIds)})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "CreateNetworkInterface",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &vpc.CreateNetworkInterfaceOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) AttachNetworkInterface(input *vpc.AttachNetworkInterfaceInput) (*vpc.AttachNetworkInterfaceOutput, error) {
	var output *vpc.AttachNetworkInterfaceOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("AttachNetworkInterface", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("AttachNetworkInterface", err)
			apiErr.RecordOpenAPIErrEvent(err,
				apiErr.EventInfoField{Key: "API", Value: "AttachNetworkInterface"},
				apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)},
				apiErr.EventInfoField{Key: "InstanceId", Value: volcengine.StringValue(input.InstanceId)})
		}
	}()
	output, err = c.VpcSvc.AttachNetworkInterfaceWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DescribeNetworkInterfaceAttributes(input *vpc.DescribeNetworkInterfaceAttributesInput) (*DescribeNetworkInterfaceAttributesOutput, error) {
	var output *DescribeNetworkInterfaceAttributesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeNetworkInterfaceAttributes", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeNetworkInterfaceAttributes", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeNetworkInterfaceAttributes"},
				apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeNetworkInterfaceAttributes",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &DescribeNetworkInterfaceAttributesOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DetachNetworkInterface(input *vpc.DetachNetworkInterfaceInput) (*vpc.DetachNetworkInterfaceOutput, error) {
	var output *vpc.DetachNetworkInterfaceOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DetachNetworkInterface", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DetachNetworkInterface", err)
			apiErr.RecordOpenAPIErrEvent(err,
				apiErr.EventInfoField{Key: "API", Value: "DetachNetworkInterface"},
				apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)},
				apiErr.EventInfoField{Key: "InstanceId", Value: volcengine.StringValue(input.InstanceId)})
		}
	}()
	output, err = c.VpcSvc.DetachNetworkInterfaceWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DeleteNetworkInterface(input *vpc.DeleteNetworkInterfaceInput) (*vpc.DeleteNetworkInterfaceOutput, error) {
	var output *vpc.DeleteNetworkInterfaceOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DeleteNetworkInterface", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DeleteNetworkInterface", err)
			apiErr.RecordOpenAPIErrEvent(err,
				apiErr.EventInfoField{Key: "API", Value: "DeleteNetworkInterface"},
				apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)})
		}
	}()
	output, err = c.VpcSvc.DeleteNetworkInterfaceWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DescribeNetworkInterfaces(input *vpc.DescribeNetworkInterfacesInput) (*DescribeNetworkInterfacesOutput, error) {
	var output *DescribeNetworkInterfacesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeNetworkInterfaces", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeNetworkInterfaces", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeNetworkInterfaces"})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeNetworkInterfaces",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &DescribeNetworkInterfacesOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) UnAssignPrivateIpAddress(input *vpc.UnassignPrivateIpAddressesInput) (*vpc.UnassignPrivateIpAddressesOutput, error) {
	var output *vpc.UnassignPrivateIpAddressesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("UnAssignPrivateIpAddress", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("UnAssignPrivateIpAddress", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "UnAssignPrivateIpAddress"})
		}
	}()
	output, err = c.VpcSvc.UnassignPrivateIpAddressesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) AssignPrivateIpAddress(input *vpc.AssignPrivateIpAddressesInput) (*vpc.AssignPrivateIpAddressesOutput, error) {
	var output *vpc.AssignPrivateIpAddressesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("AssignPrivateIpAddress", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("AssignPrivateIpAddress", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "AssignPrivateIpAddress"},
				apiErr.EventInfoField{Key: "ENI", Value: volcengine.StringValue(input.NetworkInterfaceId)})
		}
	}()
	output, err = c.VpcSvc.AssignPrivateIpAddressesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) AssignIpv6Addresses(input *AssignIpv6AddressesInput) (*AssignIpv6AddressesOutput, error) {
	var output *AssignIpv6AddressesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("AssignIpv6Addresses", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("AssignIpv6Addresses", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "AssignIpv6Addresses"})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "AssignIpv6Addresses",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &AssignIpv6AddressesOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) UnassignIpv6Addresses(input *UnassignIpv6AddressesInput) (*UnassignIpv6AddressesOutput, error) {
	var output *UnassignIpv6AddressesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("UnassignIpv6Addresses", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("UnassignIpv6Addresses", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "UnassignIpv6Addresses"})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "UnassignIpv6Addresses",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &UnassignIpv6AddressesOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DescribeHpcInstancePosition(input *DescribeHpcInstancePositionInput) (*DescribeHpcInstancePositionOutput, error) {
	var output *DescribeHpcInstancePositionOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeHpcInstancePosition", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeHpcInstancePosition", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeHpcInstancePosition"})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeHpcInstancePosition",
		Version:     "2020-04-01",
		ServiceName: "ecs",
		HttpMethod:  universal.GET,
	}
	output = &DescribeHpcInstancePositionOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DescribeSubnets(input *vpc.DescribeSubnetsInput) (*DescribeSubnetsOutput, error) {
	var output *DescribeSubnetsOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeSubnets", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeSubnets", err)
			apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeSubnets"})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeSubnets",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &DescribeSubnetsOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) DescribeSubnetAttributes(input *vpc.DescribeSubnetAttributesInput) (*DescribeSubnetAttributesOutput, error) {
	var output *DescribeSubnetAttributesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues("DescribeSubnetAttributes", fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc("DescribeSubnetAttributes", err)
			apiErr.RecordOpenAPIErrEvent(err,
				apiErr.EventInfoField{Key: "API", Value: "DescribeSubnetAttributes"},
				apiErr.EventInfoField{Key: "SubnetId", Value: volcengine.StringValue(input.SubnetId)})
		}
	}()
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeSubnetAttributes",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output = &DescribeSubnetAttributesOutput{}
	err = c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func (c *ClientSet) TagResources(input *vpc.TagResourcesInput) (*vpc.TagResourcesOutput, error) {
	var output *vpc.TagResourcesOutput
	var err error

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		metrics.OpenAPILatency.WithLabelValues(fmt.Sprintf("TagResources[%s]", volcengine.StringValue(input.ResourceType)),
			fmt.Sprint(err != nil), metrics.CelloReqErrCode(err), metrics.CelloReqId(err)).Observe(duration)
		if err != nil {
			metrics.OpenAPIErrInc(fmt.Sprintf("TagResources[%s]", volcengine.StringValue(input.ResourceType)), err)
			apiErr.RecordOpenAPIErrEvent(err,
				apiErr.EventInfoField{Key: "API", Value: fmt.Sprintf("TagResources[%s]", volcengine.StringValue(input.ResourceType))})
		}
	}()
	output, err = c.VpcSvc.TagResourcesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		err = apiErr.NewAPIRequestErr(output.Metadata, err)
		return output, err
	}
	return output, nil
}

func NewClient(region, endpoint string, credentialProvider credential.Provider) *ClientSet {
	config := volcengine.NewConfig().
		WithRegion(region).
		WithHTTPClient(&http.Client{
			Timeout: 10 * time.Second,
		}).
		WithDisableSSL(true).
		WithDynamicCredentials(func(ctx context.Context) (*credentials.Credentials, *string) {
			cred := credentialProvider.Get()
			return credentials.NewStaticCredentials(cred.AccessKeyId, cred.SecretAccessKey, cred.SessionToken), volcengine.String(region)
		}).
		WithEndpoint(volcengineutil.NewEndpoint().WithCustomerEndpoint(endpoint).GetEndpoint()).
		WithExtraUserAgent(volcengine.String(version.UserAgent()))

	if logger.GetLogLevel() == "trace" {
		config = config.WithLogger(volcengine.NewDefaultLogger()).
			WithLogLevel(volcengine.LogDebugWithInputAndOutput)
	}

	sess, _ := session.NewSession(config)
	client := ClientSet{
		VpcSvc:    vpc.New(sess),
		EcsSvc:    ecs.New(sess),
		universal: universal.New(sess),
	}
	return &client
}
