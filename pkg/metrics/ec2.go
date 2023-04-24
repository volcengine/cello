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

package metrics

import (
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"

	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
)

var (
	// OpenAPILatency latency of openapi call.
	OpenAPILatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "openapi_latency_ms",
			Help: "cello openapi call latency in ms",
		},
		[]string{"api", "error", "code", "requestId"},
	)

	// OpenAPIErr error counter of openapi call.
	OpenAPIErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openapi_error_count",
			Help: "The number of times openapi returns an error",
		},
		[]string{"api", "error", "code", "requestId"},
	)

	// MetadataLatency latency of metadata call.
	MetadataLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "metadata_latency_ms",
			Help: "cello metadata call latency in ms",
		},
		[]string{"metadata", "error", "status"},
	)

	// MetadataErr error counter of metadata call.
	MetadataErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "metadata_error_count",
			Help: "The number of times metadata returns an error",
		},
		[]string{"metadata", "error"},
	)
)

// OpenAPIErrInc help to increment count of OpenAPIErr.
func OpenAPIErrInc(api string, err error) {
	OpenAPIErr.With(prometheus.Labels{"api": api, "error": err.Error(), "code": CelloReqErrCode(err), "requestId": CelloReqId(err)}).Inc()
}

// MetadataErrInc help to increment count of MetadataErr.
func MetadataErrInc(metadata string, err error) {
	MetadataErr.With(prometheus.Labels{"metadata": metadata, "error": err.Error()}).Inc()
}

// CelloReqId return requestId of api request.
func CelloReqId(err error) string {
	if err == nil {
		return ""
	}
	var aer apiErr.APIRequestError
	if errors.As(err, &aer) {
		return aer.RequestId()
	}
	return ""
}

// CelloReqErrCode return error code of api request.
func CelloReqErrCode(err error) string {
	if err == nil {
		return ""
	}
	var aer apiErr.APIRequestError
	if errors.As(err, &aer) {
		return aer.ErrorCode()
	}
	return err.Error() // Unknown err code
}

// MetricEC2Wrapper wrapper the ec2.EC2 for metrics.
type MetricEC2Wrapper struct {
	parent ec2.EC2
}

func NewMetricEC2Wrapper(p ec2.EC2) *MetricEC2Wrapper {
	return &MetricEC2Wrapper{parent: p}
}

func (m *MetricEC2Wrapper) CreateNetworkInterface(req *vpc.CreateNetworkInterfaceInput) (*vpc.CreateNetworkInterfaceOutput, error) {
	start := time.Now()
	resp, err := m.parent.CreateNetworkInterface(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("CreateNetworkInterface", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("CreateNetworkInterface", err)
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "CreateNetworkInterface"},
			apiErr.EventInfoField{Key: "SubnetId", Value: volcengine.StringValue(req.SubnetId)},
			apiErr.EventInfoField{Key: "SecurityGroupIds", Value: volcengine.StringValueSlice(req.SecurityGroupIds)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) AttachNetworkInterface(req *vpc.AttachNetworkInterfaceInput) (*vpc.AttachNetworkInterfaceOutput, error) {
	start := time.Now()
	resp, err := m.parent.AttachNetworkInterface(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("AttachNetworkInterface", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("AttachNetworkInterface", err)
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "AttachNetworkInterface"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(req.NetworkInterfaceId)},
			apiErr.EventInfoField{Key: "InstanceId", Value: volcengine.StringValue(req.InstanceId)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DetachNetworkInterface(req *vpc.DetachNetworkInterfaceInput) (*vpc.DetachNetworkInterfaceOutput, error) {
	start := time.Now()
	resp, err := m.parent.DetachNetworkInterface(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DetachNetworkInterface", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DetachNetworkInterface", err)
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DetachNetworkInterface"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(req.NetworkInterfaceId)},
			apiErr.EventInfoField{Key: "InstanceId", Value: volcengine.StringValue(req.InstanceId)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DeleteNetworkInterface(req *vpc.DeleteNetworkInterfaceInput) (*vpc.DeleteNetworkInterfaceOutput, error) {
	start := time.Now()
	resp, err := m.parent.DeleteNetworkInterface(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DeleteNetworkInterface", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DeleteNetworkInterface", err)
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DeleteNetworkInterface"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(req.NetworkInterfaceId)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DescribeNetworkInterfaces(req *vpc.DescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error) {
	start := time.Now()
	resp, err := m.parent.DescribeNetworkInterfaces(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DescribeNetworkInterfaces", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DescribeNetworkInterfaces", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeNetworkInterfaces"})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DescribeNetworkInterfaceAttributes(req *vpc.DescribeNetworkInterfaceAttributesInput) (*ec2.DescribeNetworkInterfaceAttributesOutput, error) {
	start := time.Now()
	resp, err := m.parent.DescribeNetworkInterfaceAttributes(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DescribeNetworkInterfaceAttributes", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DescribeNetworkInterfaceAttributes", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeNetworkInterfaceAttributes"},
			apiErr.EventInfoField{Key: "NetworkInterfaceId", Value: volcengine.StringValue(req.NetworkInterfaceId)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DescribeSubnets(req *vpc.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
	start := time.Now()
	resp, err := m.parent.DescribeSubnets(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DescribeSubnets", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DescribeSubnets", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeSubnets"})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DescribeSubnetAttributes(req *vpc.DescribeSubnetAttributesInput) (*ec2.DescribeSubnetAttributesOutput, error) {
	start := time.Now()
	resp, err := m.parent.DescribeSubnetAttributes(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DescribeSubnetAttributes", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DescribeSubnetAttributes", err)
		apiErr.RecordOpenAPIErrEvent(err,
			apiErr.EventInfoField{Key: "API", Value: "DescribeSubnetAttributes"},
			apiErr.EventInfoField{Key: "SubnetId", Value: volcengine.StringValue(req.SubnetId)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DescribeInstances(req *ecs.DescribeInstancesInput) (*ecs.DescribeInstancesOutput, error) {
	start := time.Now()
	resp, err := m.parent.DescribeInstances(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DescribeInstances", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DescribeInstances", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeInstances"})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) DescribeInstanceTypes(req *ecs.DescribeInstanceTypesInput) (*ecs.DescribeInstanceTypesOutput, error) {
	start := time.Now()
	resp, err := m.parent.DescribeInstanceTypes(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("DescribeInstanceTypes", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("DescribeInstanceTypes", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "DescribeInstanceTypes"})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) AssignPrivateIpAddress(req *vpc.AssignPrivateIpAddressesInput) (*vpc.AssignPrivateIpAddressesOutput, error) {
	start := time.Now()
	resp, err := m.parent.AssignPrivateIpAddress(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("AssignPrivateIpAddress", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("AssignPrivateIpAddress", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "AssignPrivateIpAddress"},
			apiErr.EventInfoField{Key: "ENI", Value: volcengine.StringValue(req.NetworkInterfaceId)})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) UnAssignPrivateIpAddress(req *vpc.UnassignPrivateIpAddressesInput) (*vpc.UnassignPrivateIpAddressesOutput, error) {
	start := time.Now()
	resp, err := m.parent.UnAssignPrivateIpAddress(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("UnAssignPrivateIpAddress", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("UnAssignPrivateIpAddress", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "UnAssignPrivateIpAddress"})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) AssignIpv6Addresses(req *ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	start := time.Now()
	resp, err := m.parent.AssignIpv6Addresses(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("AssignIpv6Addresses", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("AssignIpv6Addresses", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "AssignIpv6Addresses"})
	}
	return resp, err
}

func (m *MetricEC2Wrapper) UnassignIpv6Addresses(req *ec2.UnassignIpv6AddressesInput) (*ec2.UnassignIpv6AddressesOutput, error) {
	start := time.Now()
	resp, err := m.parent.UnassignIpv6Addresses(req)
	duration := MsSince(start)
	OpenAPILatency.WithLabelValues("UnassignIpv6Addresses", fmt.Sprint(err != nil), CelloReqErrCode(err), CelloReqId(err)).Observe(duration)
	if err != nil {
		OpenAPIErrInc("UnassignIpv6Addresses", err)
		apiErr.RecordOpenAPIErrEvent(err, apiErr.EventInfoField{Key: "API", Value: "UnassignIpv6Addresses"})
	}
	return resp, err
}
