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
	"fmt"
	"time"

	"github.com/gdexlab/go-render/render"

	"github.com/volcengine/cello/pkg/pbrpc"
)

const (
	PodNetworkModeENIShare     = "eni_shared"
	PodNetworkModeENIExclusive = "eni_exclusive"
)

type Pod struct {
	Namespace          string    `json:"nameSpace"`
	Name               string    `json:"name"`
	SandboxContainerId string    `json:"sandboxContainerId"`
	CreateTime         time.Time `json:"createTime,omitempty"`

	NetNs string `json:"netNs,omitempty"`

	AllowEviction bool `json:"allowEviction,omitempty"`
	VpcENI        bool `json:"vpcENI,omitempty"`

	MainInterface             *pbrpc.NetworkInterface   `json:"mainInterface,omitempty"`             // Deprecated
	IsMainInterfaceSharedMode bool                      `json:"isMainInterfaceSharedMode,omitempty"` // Deprecated
	ExtraInterfaces           []*pbrpc.NetworkInterface `json:"extraInterfaces,omitempty"`           // Deprecated
	PodNetworkMode            string                    `json:"podNetworkMode,omitempty"`

	Resources []VPCResource `json:"resources,omitempty"`
}

func PodKey(podNameSpace, podName string) string {
	return fmt.Sprintf("%s/%s", podNameSpace, podName)
}

func (p *Pod) GetVPCResourceByType(rType string) []VPCResource {
	var ret []VPCResource
	if p == nil {
		return ret
	}
	for _, r := range p.Resources {
		if rType == r.Type {
			ret = append(ret, r)
		}
	}
	return ret
}

func (p *Pod) String() string {
	if p == nil {
		return ""
	}
	return render.AsCode(p)
}

type Route struct {
	// Dst means the destination address
	Dst string `json:"dst,omitempty"`
}

type PodNetwork struct {
	Name       string       `json:"name,omitempty"`
	Namespace  string       `json:"namespace,omitempty"`
	IfName     string       `json:"ifName,omitempty"`
	PodIP      pbrpc.IPSet  `json:"podIP"`
	ExtraIPs   []IPSet      `json:"extraIPs,omitempty"`
	Mac        string       `json:"mac,omitempty"`
	Gateway    pbrpc.IPSet  `json:"gateway,omitempty"`
	Cidr       *pbrpc.IPSet `json:"cidr,omitempty"`
	Route      *Route       `json:"route,omitempty"`
	ENIId      string       `json:"eniId,omitempty"`
	TrunkENIId string       `json:"trunkENIId,omitempty"`
	VlanID     uint32       `json:"vlanID,omitempty"`
}
