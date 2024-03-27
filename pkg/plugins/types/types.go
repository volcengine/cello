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
	"encoding/json"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/040"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	cniIp "github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/gdexlab/go-render/render"
	"github.com/pkg/errors"
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
	// IPVlanFlag vepa, bridge(default) or private.
	IPVlanFlag string `json:"ipVlanFlag"`

	// runtime config, support all dynamic config from meta and other runtimes
	RuntimeConfig struct {
		NetworkInterfaceConfig *NetworkInterfaceConfig `json:"com.volcengine.k8s.network-interface,omitempty"`
		Bandwidth              *BandwidthEntry         `json:"bandwidth,omitempty"`
		DeviceID               string                  `json:"deviceID,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	DriverType string `json:"driverType"`
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

type Neigh struct {
	Dst net.IP
	Mac net.HardwareAddr
}

// SetupConfig is the datapath config for pod to be set up.
type SetupConfig struct {
	DP       DataPathType
	ENIIndex int

	IfName    string       //link's name in pod
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

	// for ipVlan host netns config
	SetupInitNs bool
	IPVlanFlag  netlink.IPVlanFlag

	ExtraNeigh []Neigh
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

func ParseCmdArgs(args *skel.CmdArgs) (string, *NetConf, *K8SArgs, error) {
	// get cni request version
	versionDecoder := &cniVersion.ConfigDecoder{}
	confVersion, err := versionDecoder.Decode(args.StdinData)
	if err != nil {
		return "", nil, nil, err
	}

	// parse config in cni conf file
	conf := NetConf{}
	if err = json.Unmarshal(args.StdinData, &conf); err != nil {
		return "", nil, nil, errors.Wrap(err, "error loading config from args")
	}

	// args from a string in the form "K=V;K2=V2;..."
	// we added args like region-id/vpc-id/subnet-id
	k8sConfig := K8SArgs{}
	if err = types.LoadArgs(args.Args, &k8sConfig); err != nil {
		return "", nil, nil, errors.Wrap(err, "error loading config from args")
	}
	return confVersion, &conf, &k8sConfig, nil
}

func AppendNetworkConfigToCNIResult(cniResult *current.Result, networkConfig *SetupConfig) {
	cniInterface := &current.Interface{
		Name:    networkConfig.IfName,
		Mac:     networkConfig.Link.Attrs().HardwareAddr.String(),
		Sandbox: networkConfig.NetNSPath,
	}

	ifIndex := len(cniResult.Interfaces)
	cniResult.Interfaces = append(cniResult.Interfaces, cniInterface)

	if networkConfig.IPv4 != nil {
		cniResult.IPs = append(cniResult.IPs, &current.IPConfig{
			Version:   "4",
			Interface: &ifIndex,
			Address:   *networkConfig.IPv4,
			Gateway:   networkConfig.IPv4Gateway,
		})
		if networkConfig.DefaultRoute && networkConfig.IPv4Gateway != nil {
			cniResult.Routes = append(cniResult.Routes, &cniTypes.Route{
				Dst: net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				GW: networkConfig.IPv4Gateway,
			})
		}
	}
	if networkConfig.IPv6 != nil {
		cniResult.IPs = append(cniResult.IPs, &current.IPConfig{
			Version:   "6",
			Interface: &ifIndex,
			Address:   *networkConfig.IPv6,
			Gateway:   networkConfig.IPv6Gateway,
		})
		if networkConfig.DefaultRoute && networkConfig.IPv6Gateway != nil {
			cniResult.Routes = append(cniResult.Routes, &cniTypes.Route{
				Dst: net.IPNet{
					IP:   net.ParseIP("::"),
					Mask: net.CIDRMask(0, 128),
				},
				GW: networkConfig.IPv6Gateway,
			})
		}
	}
	for i := range networkConfig.ExtraRoutes {
		cniResult.Routes = append(cniResult.Routes, &networkConfig.ExtraRoutes[i])
	}
}
