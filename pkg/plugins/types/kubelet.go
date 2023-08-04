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

// ResourceInfo is struct to hold Pod device allocation information.
type ResourceInfo struct {
	Index     int
	DeviceIDs []string
}

// ContainerResourceInfo contains information about the resource assigned to a container
type ContainerResourceInfo struct {
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

// ResourceClient provides a kubelet Pod resource handle.
type ResourceClient interface {
	// GetPodResourceMap returns an instance of a map of Pod ResourceInfo given a (Pod name, namespace) tuple.
	GetPodResourceMap(podNamespace, podName string) (map[string]*ResourceInfo, error)
	GetPodContainerResourceMap(podNamespace, podName string) ([]*ContainerResourceInfo, error)
}
