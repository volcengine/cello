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
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/version"
)

type ClientSet struct {
	VpcSvc    *vpc.VPC
	EcsSvc    *ecs.ECS
	universal *universal.Universal
}

func (c *ClientSet) DescribeInstances(input *ecs.DescribeInstancesInput) (*ecs.DescribeInstancesOutput, error) {
	start := time.Now()
	output, err := c.EcsSvc.DescribeInstancesWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeInstances", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeInstances", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeInstances"})
	}
	return output, err
}

func (c *ClientSet) DescribeInstanceTypes(input *ecs.DescribeInstanceTypesInput) (*DescribeInstanceTypesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeInstanceTypes",
		Version:     "2020-04-01",
		ServiceName: "ecs",
		HttpMethod:  universal.GET,
	}
	output := &DescribeInstanceTypesOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeInstanceTypes", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeInstanceTypes", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeInstanceTypes"})
	}
	return output, err
}

func (c *ClientSet) CreateNetworkInterface(input *CreateNetworkInterfaceInput) (*vpc.CreateNetworkInterfaceOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "CreateNetworkInterface",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &vpc.CreateNetworkInterfaceOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("CreateNetworkInterface", start)
	}
	metrics.OpenAPIStatisticRecord("CreateNetworkInterface", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "CreateNetworkInterface"},
			apiErr.EventInfoField{Key: "SubnetId", Value: volcengine.StringValue(input.SubnetId)},
			apiErr.EventInfoField{Key: "SecurityGroupIds", Value: volcengine.StringValueSlice(input.SecurityGroupIds)})
	}
	return output, err
}

func (c *ClientSet) AttachNetworkInterface(input *vpc.AttachNetworkInterfaceInput) (*vpc.AttachNetworkInterfaceOutput, error) {
	start := time.Now()
	output, err := c.VpcSvc.AttachNetworkInterfaceWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("AttachNetworkInterface", start)
	}
	metrics.OpenAPIStatisticRecord("AttachNetworkInterface", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "AttachNetworkInterface"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)},
			apiErr.EventInfoField{Key: "InstanceId", Value: volcengine.StringValue(input.InstanceId)})
	}
	return output, err
}

func (c *ClientSet) DescribeNetworkInterfaceAttributes(input *vpc.DescribeNetworkInterfaceAttributesInput) (*DescribeNetworkInterfaceAttributesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeNetworkInterfaceAttributes",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}

	start := time.Now()
	output := &DescribeNetworkInterfaceAttributesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)

	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeNetworkInterfaceAttributes", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeNetworkInterfaceAttributes", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeNetworkInterfaceAttributes"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)})
	}
	return output, err
}

func (c *ClientSet) DetachNetworkInterface(input *vpc.DetachNetworkInterfaceInput) (*vpc.DetachNetworkInterfaceOutput, error) {
	start := time.Now()
	output, err := c.VpcSvc.DetachNetworkInterfaceWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DetachNetworkInterface", start)
	}
	metrics.OpenAPIStatisticRecord("DetachNetworkInterface", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DetachNetworkInterface"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)},
			apiErr.EventInfoField{Key: "InstanceId", Value: volcengine.StringValue(input.InstanceId)})
	}
	return output, err
}

func (c *ClientSet) DeleteNetworkInterface(input *vpc.DeleteNetworkInterfaceInput) (*vpc.DeleteNetworkInterfaceOutput, error) {
	start := time.Now()
	output, err := c.VpcSvc.DeleteNetworkInterfaceWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DeleteNetworkInterface", start)
	}
	metrics.OpenAPIStatisticRecord("DeleteNetworkInterface", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DeleteNetworkInterface"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(input.NetworkInterfaceId)})
	}
	return output, err
}

func (c *ClientSet) DescribeNetworkInterfaces(input *vpc.DescribeNetworkInterfacesInput) (*DescribeNetworkInterfacesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeNetworkInterfaces",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeNetworkInterfacesOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeNetworkInterfaces", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeNetworkInterfaces", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeNetworkInterfaces"})
	}
	return output, err
}

func (c *ClientSet) UnAssignPrivateIpAddress(input *vpc.UnassignPrivateIpAddressesInput) (*vpc.UnassignPrivateIpAddressesOutput, error) {
	start := time.Now()
	output, err := c.VpcSvc.UnassignPrivateIpAddressesWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("UnAssignPrivateIpAddress", start)
	}
	metrics.OpenAPIStatisticRecord("UnAssignPrivateIpAddress", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "UnAssignPrivateIpAddress"})
	}
	return output, err
}

func (c *ClientSet) AssignPrivateIpAddress(input *vpc.AssignPrivateIpAddressesInput) (*vpc.AssignPrivateIpAddressesOutput, error) {
	start := time.Now()
	output, err := c.VpcSvc.AssignPrivateIpAddressesWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("AssignPrivateIpAddress", start)
	}
	metrics.OpenAPIStatisticRecord("AssignPrivateIpAddress", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "AssignPrivateIpAddress"},
			apiErr.EventInfoField{Key: "ENI", Value: volcengine.StringValue(input.NetworkInterfaceId)})
	}
	return output, err
}

func (c *ClientSet) AssignIpv6Addresses(input *AssignIpv6AddressesInput) (*AssignIpv6AddressesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "AssignIpv6Addresses",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &AssignIpv6AddressesOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("AssignIpv6Addresses", start)
	}
	metrics.OpenAPIStatisticRecord("AssignIpv6Addresses", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "AssignIpv6Addresses"})
	}
	return output, err
}

func (c *ClientSet) UnassignIpv6Addresses(input *UnassignIpv6AddressesInput) (*UnassignIpv6AddressesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "UnassignIpv6Addresses",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &UnassignIpv6AddressesOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("UnassignIpv6Addresses", start)
	}
	metrics.OpenAPIStatisticRecord("UnassignIpv6Addresses", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "UnassignIpv6Addresses"})
	}
	return output, err
}

func (c *ClientSet) DescribeHpcInstancePosition(input *DescribeHpcInstancePositionInput) (*DescribeHpcInstancePositionOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeHpcInstancePosition",
		Version:     "2020-04-01",
		ServiceName: "ecs",
		HttpMethod:  universal.GET,
	}
	output := &DescribeHpcInstancePositionOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeHpcInstancePosition", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeHpcInstancePosition", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeHpcInstancePosition"})
	}
	return output, err
}

func (c *ClientSet) DescribeSubnets(input *vpc.DescribeSubnetsInput) (*DescribeSubnetsOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeSubnets",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeSubnetsOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeSubnets", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeSubnets", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeSubnets"})
	}
	return output, err
}

func (c *ClientSet) DescribeSubnetAttributes(input *vpc.DescribeSubnetAttributesInput) (*DescribeSubnetAttributesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeSubnetAttributes",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeSubnetAttributesOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeSubnetAttributes", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeSubnetAttributes", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DescribeSubnetAttributes"},
			apiErr.EventInfoField{Key: "SubnetId", Value: volcengine.StringValue(input.SubnetId)})
	}
	return output, err
}

func (c *ClientSet) TagResources(input *vpc.TagResourcesInput) (*vpc.TagResourcesOutput, error) {
	start := time.Now()
	output, err := c.VpcSvc.TagResourcesWithContext(context.TODO(), input)
	status := apiErr.NewAPIRequestStatus(getMetadataFromOutput(output), err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("TagResources", start)
	}
	metrics.OpenAPIStatisticRecord("TagResources", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: fmt.Sprintf("TagResources[%s]", volcengine.StringValue(input.ResourceType))})
	}
	return output, err
}

func (c *ClientSet) DescribeTrunkAssociations(input *DescribeTrunkAssociationsInput) (*DescribeTrunkAssociationsOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeTrunkAssociations",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeTrunkAssociationsOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DescribeTrunkAssociations", start)
	}
	metrics.OpenAPIStatisticRecord("DescribeTrunkAssociations", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DescribeTrunkAssociations"},
			apiErr.EventInfoField{Key: "TrunkInterfaceId", Value: volcengine.StringValue(input.TrunkInterfaceId)})
	}
	return output, err
}

func (c *ClientSet) DisassociateTrunkInterface(input *DisassociateTrunkInterfaceInput) (*DisassociateTrunkInterfaceOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DisassociateTrunkInterface",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DisassociateTrunkInterfaceOutput{}

	start := time.Now()
	err := c.universal.DoCallWithType(reqInfo, input, output)
	status := apiErr.NewAPIRequestStatus(output.Metadata, err)
	if status.ErrorCode() != apiErr.ClientErr {
		metrics.OpenAPILatencyRecord("DisassociateTrunkInterface", start)
	}
	metrics.OpenAPIStatisticRecord("DisassociateTrunkInterface", status.HttpCode(), status.ErrorCode())

	if err = status.GetError(); err != nil {
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DisassociateTrunkInterface"},
			apiErr.EventInfoField{Key: "TrunkInterfaceId", Value: volcengine.StringValue(input.TrunkInterfaceId)},
			apiErr.EventInfoField{Key: "BranchInterfaceId", Value: volcengine.StringValue(input.BranchInterfaceId)})
	}
	return output, err
}

func NewClient(region, endpoint, endpointConfigPath string, cred *credentials.Credentials) *ClientSet {
	config := volcengine.NewConfig().
		WithRegion(region).
		WithHTTPClient(&http.Client{
			Timeout: 10 * time.Second,
		}).
		WithCredentials(cred).
		WithExtraUserAgent(volcengine.String(version.UserAgent()))

	if len(endpointConfigPath) != 0 {
		config = config.WithEndpointConfigState(true).
			WithEndpointConfigPath(endpointConfigPath)
	} else if len(endpoint) != 0 {
		config = config.WithEndpoint(volcengineutil.NewEndpoint().WithCustomerEndpoint(endpoint).GetEndpoint())
	}

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
