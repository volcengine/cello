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

package types

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	PodInfoVersion10 = "1.0"
)

type PodInfo struct {
	Version           string              `json:"version,omitempty"`
	CreateTime        v1.Time             `json:"createTime,omitempty"`
	SandboxID         string              `json:"sandboxID,omitempty"`
	Namespace         string              `json:"namespace,omitempty"`
	Name              string              `json:"name,omitempty"`
	ResourceMap       *ResourceMap        `json:"resourceMap,omitempty"`
	NetNs             string              `json:"netns,omitempty"`
	NetworkInterfaces []*NetworkInterface `json:"networkInterfaces,omitempty"`
}

type ResourceMap struct {
	Containers []*ContainerResource `json:"containers"`
}

type NetworkInterface struct {
	Name   string                  `json:"name,omitempty"`
	CNI    string                  `json:"cni,omitempty"`
	Mac    string                  `json:"mac,omitempty"`
	IPs    []string                `json:"ips,omitempty"`
	Device *NetworkInterfaceDevice `json:"device,omitempty"`
}

type NetworkInterfaceDevice struct {
	ResourceName string `json:"resourceName,omitempty"`
	DeviceID     string `json:"deviceID,omitempty"`
	PciAddress   string `json:"pciAddress,omitempty"`
}

// ContainerResource contains information about the resource assigned to a container
type ContainerResource struct {
	Name    string              `json:"name,omitempty"`
	Devices []*ContainerDevices `json:"devices,omitempty"`
}

// ContainerDevices contains information about the devices assigned to a container
type ContainerDevices struct {
	ResourceName string        `json:"resource_name,omitempty"`
	DeviceIds    []string      `json:"device_ids,omitempty"`
	Topology     *TopologyInfo `json:"topology,omitempty"`
}

// TopologyInfo describes hardware topology of the resource
type TopologyInfo struct {
	Nodes []*NUMANode
}

// NUMANode representation of NUMA node
type NUMANode struct {
	ID int64
}
