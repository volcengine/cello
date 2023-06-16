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

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/volcengine/cello/pkg/provider/volcengine/ec2 (interfaces: EC2)

// Package mock is a generated GoMock package.
package mock

import (
	gomock "github.com/golang/mock/gomock"
	ec2 "github.com/volcengine/cello/pkg/provider/volcengine/ec2"
	ecs "github.com/volcengine/volcengine-go-sdk/service/ecs"
	vpc "github.com/volcengine/volcengine-go-sdk/service/vpc"
	reflect "reflect"
)

// MockEC2 is a mock of EC2 interface
type MockEC2 struct {
	ctrl     *gomock.Controller
	recorder *MockEC2MockRecorder
}

// MockEC2MockRecorder is the mock recorder for MockEC2
type MockEC2MockRecorder struct {
	mock *MockEC2
}

// NewMockEC2 creates a new mock instance
func NewMockEC2(ctrl *gomock.Controller) *MockEC2 {
	mock := &MockEC2{ctrl: ctrl}
	mock.recorder = &MockEC2MockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEC2) EXPECT() *MockEC2MockRecorder {
	return m.recorder
}

// AssignIpv6Addresses mocks base method
func (m *MockEC2) AssignIpv6Addresses(arg0 *ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignIpv6Addresses", arg0)
	ret0, _ := ret[0].(*ec2.AssignIpv6AddressesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AssignIpv6Addresses indicates an expected call of AssignIpv6Addresses
func (mr *MockEC2MockRecorder) AssignIpv6Addresses(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignIpv6Addresses", reflect.TypeOf((*MockEC2)(nil).AssignIpv6Addresses), arg0)
}

// AssignPrivateIpAddress mocks base method
func (m *MockEC2) AssignPrivateIpAddress(arg0 *vpc.AssignPrivateIpAddressesInput) (*vpc.AssignPrivateIpAddressesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignPrivateIpAddress", arg0)
	ret0, _ := ret[0].(*vpc.AssignPrivateIpAddressesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AssignPrivateIpAddress indicates an expected call of AssignPrivateIpAddress
func (mr *MockEC2MockRecorder) AssignPrivateIpAddress(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignPrivateIpAddress", reflect.TypeOf((*MockEC2)(nil).AssignPrivateIpAddress), arg0)
}

// AttachNetworkInterface mocks base method
func (m *MockEC2) AttachNetworkInterface(arg0 *vpc.AttachNetworkInterfaceInput) (*vpc.AttachNetworkInterfaceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AttachNetworkInterface", arg0)
	ret0, _ := ret[0].(*vpc.AttachNetworkInterfaceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AttachNetworkInterface indicates an expected call of AttachNetworkInterface
func (mr *MockEC2MockRecorder) AttachNetworkInterface(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AttachNetworkInterface", reflect.TypeOf((*MockEC2)(nil).AttachNetworkInterface), arg0)
}

// CreateNetworkInterface mocks base method
func (m *MockEC2) CreateNetworkInterface(arg0 *ec2.CreateNetworkInterfaceInput) (*vpc.CreateNetworkInterfaceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateNetworkInterface", arg0)
	ret0, _ := ret[0].(*vpc.CreateNetworkInterfaceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateNetworkInterface indicates an expected call of CreateNetworkInterface
func (mr *MockEC2MockRecorder) CreateNetworkInterface(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNetworkInterface", reflect.TypeOf((*MockEC2)(nil).CreateNetworkInterface), arg0)
}

// DeleteNetworkInterface mocks base method
func (m *MockEC2) DeleteNetworkInterface(arg0 *vpc.DeleteNetworkInterfaceInput) (*vpc.DeleteNetworkInterfaceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteNetworkInterface", arg0)
	ret0, _ := ret[0].(*vpc.DeleteNetworkInterfaceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteNetworkInterface indicates an expected call of DeleteNetworkInterface
func (mr *MockEC2MockRecorder) DeleteNetworkInterface(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteNetworkInterface", reflect.TypeOf((*MockEC2)(nil).DeleteNetworkInterface), arg0)
}

// DescribeInstanceTypes mocks base method
func (m *MockEC2) DescribeInstanceTypes(arg0 *ecs.DescribeInstanceTypesInput) (*ec2.DescribeInstanceTypesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeInstanceTypes", arg0)
	ret0, _ := ret[0].(*ec2.DescribeInstanceTypesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeInstanceTypes indicates an expected call of DescribeInstanceTypes
func (mr *MockEC2MockRecorder) DescribeInstanceTypes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeInstanceTypes", reflect.TypeOf((*MockEC2)(nil).DescribeInstanceTypes), arg0)
}

// DescribeInstances mocks base method
func (m *MockEC2) DescribeInstances(arg0 *ecs.DescribeInstancesInput) (*ecs.DescribeInstancesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeInstances", arg0)
	ret0, _ := ret[0].(*ecs.DescribeInstancesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeInstances indicates an expected call of DescribeInstances
func (mr *MockEC2MockRecorder) DescribeInstances(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeInstances", reflect.TypeOf((*MockEC2)(nil).DescribeInstances), arg0)
}

// DescribeNetworkInterfaceAttributes mocks base method
func (m *MockEC2) DescribeNetworkInterfaceAttributes(arg0 *vpc.DescribeNetworkInterfaceAttributesInput) (*ec2.DescribeNetworkInterfaceAttributesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeNetworkInterfaceAttributes", arg0)
	ret0, _ := ret[0].(*ec2.DescribeNetworkInterfaceAttributesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeNetworkInterfaceAttributes indicates an expected call of DescribeNetworkInterfaceAttributes
func (mr *MockEC2MockRecorder) DescribeNetworkInterfaceAttributes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeNetworkInterfaceAttributes", reflect.TypeOf((*MockEC2)(nil).DescribeNetworkInterfaceAttributes), arg0)
}

// DescribeNetworkInterfaces mocks base method
func (m *MockEC2) DescribeNetworkInterfaces(arg0 *vpc.DescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeNetworkInterfaces", arg0)
	ret0, _ := ret[0].(*ec2.DescribeNetworkInterfacesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeNetworkInterfaces indicates an expected call of DescribeNetworkInterfaces
func (mr *MockEC2MockRecorder) DescribeNetworkInterfaces(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeNetworkInterfaces", reflect.TypeOf((*MockEC2)(nil).DescribeNetworkInterfaces), arg0)
}

// DescribeSubnetAttributes mocks base method
func (m *MockEC2) DescribeSubnetAttributes(arg0 *vpc.DescribeSubnetAttributesInput) (*ec2.DescribeSubnetAttributesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeSubnetAttributes", arg0)
	ret0, _ := ret[0].(*ec2.DescribeSubnetAttributesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeSubnetAttributes indicates an expected call of DescribeSubnetAttributes
func (mr *MockEC2MockRecorder) DescribeSubnetAttributes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeSubnetAttributes", reflect.TypeOf((*MockEC2)(nil).DescribeSubnetAttributes), arg0)
}

// DescribeSubnets mocks base method
func (m *MockEC2) DescribeSubnets(arg0 *vpc.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DescribeSubnets", arg0)
	ret0, _ := ret[0].(*ec2.DescribeSubnetsOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeSubnets indicates an expected call of DescribeSubnets
func (mr *MockEC2MockRecorder) DescribeSubnets(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeSubnets", reflect.TypeOf((*MockEC2)(nil).DescribeSubnets), arg0)
}

// DetachNetworkInterface mocks base method
func (m *MockEC2) DetachNetworkInterface(arg0 *vpc.DetachNetworkInterfaceInput) (*vpc.DetachNetworkInterfaceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DetachNetworkInterface", arg0)
	ret0, _ := ret[0].(*vpc.DetachNetworkInterfaceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DetachNetworkInterface indicates an expected call of DetachNetworkInterface
func (mr *MockEC2MockRecorder) DetachNetworkInterface(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DetachNetworkInterface", reflect.TypeOf((*MockEC2)(nil).DetachNetworkInterface), arg0)
}

// TagResources mocks base method
func (m *MockEC2) TagResources(arg0 *vpc.TagResourcesInput) (*vpc.TagResourcesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TagResources", arg0)
	ret0, _ := ret[0].(*vpc.TagResourcesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TagResources indicates an expected call of TagResources
func (mr *MockEC2MockRecorder) TagResources(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TagResources", reflect.TypeOf((*MockEC2)(nil).TagResources), arg0)
}

// UnAssignPrivateIpAddress mocks base method
func (m *MockEC2) UnAssignPrivateIpAddress(arg0 *vpc.UnassignPrivateIpAddressesInput) (*vpc.UnassignPrivateIpAddressesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnAssignPrivateIpAddress", arg0)
	ret0, _ := ret[0].(*vpc.UnassignPrivateIpAddressesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnAssignPrivateIpAddress indicates an expected call of UnAssignPrivateIpAddress
func (mr *MockEC2MockRecorder) UnAssignPrivateIpAddress(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnAssignPrivateIpAddress", reflect.TypeOf((*MockEC2)(nil).UnAssignPrivateIpAddress), arg0)
}

// UnassignIpv6Addresses mocks base method
func (m *MockEC2) UnassignIpv6Addresses(arg0 *ec2.UnassignIpv6AddressesInput) (*ec2.UnassignIpv6AddressesOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnassignIpv6Addresses", arg0)
	ret0, _ := ret[0].(*ec2.UnassignIpv6AddressesOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnassignIpv6Addresses indicates an expected call of UnassignIpv6Addresses
func (mr *MockEC2MockRecorder) UnassignIpv6Addresses(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnassignIpv6Addresses", reflect.TypeOf((*MockEC2)(nil).UnassignIpv6Addresses), arg0)
}
