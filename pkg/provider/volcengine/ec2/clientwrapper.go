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
	"net/http"
	"time"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	"github.com/volcengine/volcengine-go-sdk/volcengine/universal"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineutil"

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
	output, err := c.EcsSvc.DescribeInstancesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DescribeInstanceTypes(input *ecs.DescribeInstanceTypesInput) (*DescribeInstanceTypesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeInstanceTypes",
		Version:     "2020-04-01",
		ServiceName: "ecs",
		HttpMethod:  universal.GET,
	}
	output := &DescribeInstanceTypesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) CreateNetworkInterface(input *CreateNetworkInterfaceInput) (*vpc.CreateNetworkInterfaceOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "CreateNetworkInterface",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &vpc.CreateNetworkInterfaceOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) AttachNetworkInterface(input *vpc.AttachNetworkInterfaceInput) (*vpc.AttachNetworkInterfaceOutput, error) {
	output, err := c.VpcSvc.AttachNetworkInterfaceWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DescribeNetworkInterfaceAttributes(input *vpc.DescribeNetworkInterfaceAttributesInput) (*DescribeNetworkInterfaceAttributesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeNetworkInterfaceAttributes",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeNetworkInterfaceAttributesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DetachNetworkInterface(input *vpc.DetachNetworkInterfaceInput) (*vpc.DetachNetworkInterfaceOutput, error) {
	output, err := c.VpcSvc.DetachNetworkInterfaceWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DeleteNetworkInterface(input *vpc.DeleteNetworkInterfaceInput) (*vpc.DeleteNetworkInterfaceOutput, error) {
	output, err := c.VpcSvc.DeleteNetworkInterfaceWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DescribeNetworkInterfaces(input *vpc.DescribeNetworkInterfacesInput) (*DescribeNetworkInterfacesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeNetworkInterfaces",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeNetworkInterfacesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) UnAssignPrivateIpAddress(input *vpc.UnassignPrivateIpAddressesInput) (*vpc.UnassignPrivateIpAddressesOutput, error) {
	output, err := c.VpcSvc.UnassignPrivateIpAddressesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) AssignPrivateIpAddress(input *vpc.AssignPrivateIpAddressesInput) (*vpc.AssignPrivateIpAddressesOutput, error) {
	output, err := c.VpcSvc.AssignPrivateIpAddressesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) AssignIpv6Addresses(input *AssignIpv6AddressesInput) (*AssignIpv6AddressesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "AssignIpv6Addresses",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &AssignIpv6AddressesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) UnassignIpv6Addresses(input *UnassignIpv6AddressesInput) (*UnassignIpv6AddressesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "UnassignIpv6Addresses",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &UnassignIpv6AddressesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DescribeSubnets(input *vpc.DescribeSubnetsInput) (*DescribeSubnetsOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeSubnets",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeSubnetsOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) DescribeSubnetAttributes(input *vpc.DescribeSubnetAttributesInput) (*DescribeSubnetAttributesOutput, error) {
	reqInfo := universal.RequestUniversal{
		Action:      "DescribeSubnetAttributes",
		Version:     "2020-04-01",
		ServiceName: "vpc",
		HttpMethod:  universal.GET,
	}
	output := &DescribeSubnetAttributesOutput{}
	err := c.universal.DoCallWithType(reqInfo, input, output)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
	}
	return output, nil
}

func (c *ClientSet) TagResources(input *vpc.TagResourcesInput) (*vpc.TagResourcesOutput, error) {
	output, err := c.VpcSvc.TagResourcesWithContext(context.TODO(), input)
	if err != nil || output.Metadata.Error != nil {
		return output, apiErr.NewAPIRequestErr(output.Metadata, err)
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
