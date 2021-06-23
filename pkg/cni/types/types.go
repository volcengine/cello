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
	"net"

	"github.com/containernetworking/cni/pkg/types"
	cniIp "github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/gdexlab/go-render/render"
	"github.com/vishvananda/netlink"

	celloTypes "github.com/volcengine/cello/types"
)

const (
	// CelloChainer is the type of CNI conflist for chained CNI call.
	CelloChainer = "cello-chainer"

	// NetworkInterfaceConfigTypeTrunk is the trunk type of NetworkInterfaceConfig runtimeConfig
	NetworkInterfaceConfigTypeTrunk = "trunk"
)

// NetConf is the cni network config.
type NetConf struct {
	// CNIVersion for CNI calls.
	CNIVersion string `json:"cniVersion,omitempty"`
	// Name is the name of netconf.
	Name string `json:"name"`
	// Type is CNI type, should be cello.
	Type string `json:"type"`
	// RedirectToHostCIDRs, all traffic targeting these CIDRs will be redirected to host.
	RedirectToHostCIDRs []string `json:"redirectToHostCIDRs"`
	// LocalFastPath is a switch to determine weather cello should set up fast path between host and pod.
	// Currently only support IPVlan and Vlan (by adding additional veth pair) driver.
	LocalFastPath bool `json:"localFastPath"`

	// runtime config, support all dynamic config from meta and other runtimes
	RuntimeConfig struct {
		NetworkInterfaceConfig *NetworkInterfaceConfig `json:"com.volcengine.k8s.network-interface,omitempty"`
		Bandwidth              *BandwidthEntry         `json:"bandwidth,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

// K8SArgs is CNI args of kubernetes.
type K8SArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString // nolint
	K8S_POD_NAMESPACE          types.UnmarshallableString // nolint
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString // nolint
	K8S_POD_UID                types.UnmarshallableString // nolint
}

// DataPathType is the interface type of pod.
type DataPathType int

const (
	IPVlan DataPathType = iota
	ENI
	Vlan
)

// IPType indicates ENI's IP address binding.
type IPType int

const (
	ENIMultiIP IPType = iota
	ENISingleIP
)

// SetupConfig is the datapath config for pod to be set up.
type SetupConfig struct {
	DP       DataPathType
	ENIIndex int

	IfName    string       //interface Name in pod
	Link      netlink.Link //pod's interface
	NetNSPath string       //ns path of pod
	NetNs     *ns.NetNS

	IPv4        *net.IPNet
	IPv4Gateway net.IP

	IPv6        *net.IPNet
	IPv6Gateway net.IP

	BandWidth *BandwidthEntry

	DefaultRoute bool
	ExtraRoutes  []types.Route
	PolicyRoute  bool

	RedirectToHostCIDRs []*net.IPNet // used by nodeLocalDns etc.
	LocalFastPath       bool
	VethNameInHost      string
	HostLink            netlink.Link // host master, eth0
	HostIPSet           *celloTypes.IPSet

	// for vlan
	Vid          uint32
	HardwareAddr net.HardwareAddr
}

func (c *SetupConfig) String() string {
	if c == nil {
		return ""
	}
	return render.AsCode(c)
}

// TeardownConfig is the datapath config for cello-cni to teardown.
type TeardownConfig struct {
	DP             DataPathType
	ContainerIPNet *celloTypes.IPSet
}

func (c *TeardownConfig) String() string {
	if c == nil {
		return ""
	}
	return render.AsCode(c)
}

// BandwidthEntry for CNI BandwidthEntry
type BandwidthEntry struct {
	IngressRate  int `json:"ingressRate"`
	IngressBurst int `json:"ingressBurst"`

	EgressRate  int `json:"egressRate"`
	EgressBurst int `json:"egressBurst"`
}

func (bw *BandwidthEntry) IsZero() bool {
	return bw.IngressBurst == 0 && bw.IngressRate == 0 && bw.EgressBurst == 0 && bw.EgressRate == 0
}

// NetworkInterfaceConfig describes network interface configs used by cello CNI.
type NetworkInterfaceConfig struct {
	Type  string                       `json:"type"`
	IPs   []*cniIp.IP                  `json:"ips,omitempty"`
	Mac   string                       `json:"mac,omitempty"`
	Trunk *NetworkInterfaceTrunkConfig `json:"trunk,omitempty"`
}

// NetworkInterfaceTrunkConfig is the branch ENI information used by Vlan driver.
type NetworkInterfaceTrunkConfig struct {
	VlanID   string `json:"vlanID,omitempty"`
	TrunkMac string `json:"trunkMac,omitempty"`
}
