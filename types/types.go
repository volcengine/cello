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
	"net"
	"strings"

	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/utils/math"
)

const (
	// DefaultIfName is the default network interface for the pods
	DefaultIfName = "eth0"
)

type TrunkInfo struct {
	EniID       string `json:"eniID"`
	Mac         string `json:"mac"`
	BranchLimit int    `json:"branchLimit"`
}

type IPSet struct {
	IPv4 net.IP
	IPv6 net.IP
}

func (s *IPSet) String() string {
	if s == nil {
		return ""
	}
	var result []string
	if s.IPv4 != nil {
		result = append(result, s.IPv4.String())
	}
	if s.IPv6 != nil {
		result = append(result, s.IPv6.String())
	}
	return strings.Join(result, "-")
}

func (s *IPSet) GetIPv4() string {
	if s != nil && s.IPv4 != nil {
		return s.IPv4.String()
	}
	return ""
}

func (s *IPSet) GetIPv6() string {
	if s != nil && s.IPv6 != nil {
		return s.IPv6.String()
	}
	return ""
}

func (s *IPSet) ToPb() *pbrpc.IPSet {
	if s == nil {
		return nil
	}
	var ipv4, ipv6 string
	if s.IPv4 != nil {
		ipv4 = s.IPv4.String()
	}
	if s.IPv6 != nil {
		ipv6 = s.IPv6.String()
	}
	return &pbrpc.IPSet{
		IPv4: ipv4,
		IPv6: ipv6,
	}
}

func (s *IPSet) ToPbWithMask(cidr *IPNetSet) *pbrpc.IPSet {
	if s == nil {
		return nil
	}
	var ipv4, ipv6 string
	if s.IPv4 != nil {
		t := &net.IPNet{
			IP: s.IPv4,
		}
		if cidr != nil && cidr.IPv4 != nil {
			t.Mask = cidr.IPv4.Mask
		} else {
			t.Mask = net.CIDRMask(32, 32)
		}
		ipv4 = t.String()
	}
	if s.IPv6 != nil {
		t := &net.IPNet{
			IP: s.IPv6,
		}
		if cidr != nil && cidr.IPv6 != nil {
			t.Mask = cidr.IPv6.Mask
		} else {
			t.Mask = net.CIDRMask(128, 128)
		}
		ipv6 = t.String()
	}
	return &pbrpc.IPSet{
		IPv4: ipv4,
		IPv6: ipv6,
	}
}

// PairIPs pair ipv4s and ipv6s to IPSet slice
func PairIPs(ipv4s, ipv6s []net.IP) []IPSet {
	result := make([]IPSet, math.Max(len(ipv4s), len(ipv6s)))
	for i, ip := range ipv4s {
		result[i].IPv4 = ip
	}
	for i, ip := range ipv6s {
		result[i].IPv6 = ip
	}
	return result
}

type IPNetSet struct {
	IPv4 *net.IPNet
	IPv6 *net.IPNet
}

func (s *IPNetSet) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("IPv4Cidr: %s, IPv6Cidr: %s", s.IPv4.String(), s.IPv6.String())
}

func (s *IPNetSet) ToPb() *pbrpc.IPSet {
	var ipv4, ipv6 string
	if s != nil && s.IPv4 != nil {
		ipv4 = s.IPv4.String()
	}
	if s != nil && s.IPv6 != nil {
		ipv6 = s.IPv6.String()
	}
	return &pbrpc.IPSet{
		IPv4: ipv4,
		IPv6: ipv6,
	}
}

type Subnet struct {
	ID         string
	Gateway    *IPSet
	GatewayMac net.HardwareAddr
	CIDR       *IPNetSet
}

func (s *Subnet) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("ID: %s, Gateway: %s, GatewayMac: %s, CIDR: %s",
		s.ID, s.Gateway.String(), s.GatewayMac.String(), s.CIDR.String())
}

// ENI with all necessary information about ENI
type ENI struct {
	ID               string
	Mac              net.HardwareAddr
	PrimaryIP        IPSet
	Subnet           Subnet
	SecurityGroupIDs []string
	Trunk            bool // is trunk eni ?
}

func (e *ENI) GetID() string {
	if e == nil {
		return ""
	}
	return e.ID
}

func (e *ENI) GetType() string {
	return NetResourceTypeEni
}

func (e *ENI) GetVPCResource() VPCResource {
	return VPCResource{
		Type:   NetResourceTypeEni,
		ID:     e.GetID(),
		ENIId:  e.ID,
		ENIMac: e.Mac.String(),
		IPv4:   e.PrimaryIP.GetIPv4(),
		IPv6:   e.PrimaryIP.GetIPv6(),
	}
}

func (e *ENI) String() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("ID: %s, Mac: %s, PrimaryIP: %s, Subnet: %s",
		e.ID, e.Mac.String(), e.PrimaryIP.String(), e.Subnet.String())
}

func (e *ENI) ToPb() *pbrpc.ENI {
	if e == nil {
		return nil
	}
	var ipv4Gateway, ipv6Gateway, mac, gatewayMac string
	if e.Mac != nil {
		mac = e.Mac.String()
	}
	if e.Subnet.Gateway != nil {
		if e.Subnet.Gateway.IPv4 != nil {
			ipv4Gateway = e.Subnet.Gateway.IPv4.String()
		}
		if e.Subnet.Gateway.IPv6 != nil {
			ipv6Gateway = e.Subnet.Gateway.IPv6.String()
		}
		if e.Subnet.GatewayMac != nil {
			gatewayMac = e.Subnet.GatewayMac.String()
		}
	}
	return &pbrpc.ENI{
		ID:          e.ID,
		Mac:         mac,
		IPv4Gateway: ipv4Gateway,
		IPv6Gateway: ipv6Gateway,
		GatewayMac:  gatewayMac,
		Subnet:      e.Subnet.CIDR.ToPb(),
	}
}

type ENIIP struct {
	ENI   *ENI
	IPSet IPSet
}

func (e *ENIIP) GetID() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s", e.ENI.GetID(), e.IPSet.String())
}

func (e *ENIIP) GetType() string {
	return NetResourceTypeEniIp
}

func (e *ENIIP) GetVPCResource() VPCResource {
	return VPCResource{
		Type:   e.GetType(),
		ID:     e.GetID(),
		ENIId:  e.ENI.ID,
		ENIMac: e.ENI.Mac.String(),
		IPv4:   e.IPSet.GetIPv4(),
		IPv6:   e.IPSet.GetIPv6(),
	}
}

// NetResourceType
const (
	NetResourceTypeEni   = "eni"
	NetResourceTypeEniIp = "eniIp"
)

// VPCResource is network resource of vpc
type VPCResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`

	ENIId  string `json:"ENIId"`
	ENIMac string `json:"ENIMac"`
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
}

type VPCResourceAllocated struct {
	Owner    string
	Resource VPCResource
}

func (r *VPCResource) ToNetResource() (res NetResource) {
	mac, err := net.ParseMAC(r.ENIMac)
	if err != nil {
		return
	}
	switch r.Type {
	case NetResourceTypeEni:
		res = &ENI{
			ID:  r.ENIId,
			Mac: mac,
			PrimaryIP: IPSet{
				IPv4: net.ParseIP(r.IPv4),
				IPv6: net.ParseIP(r.IPv6),
			},
			Subnet: Subnet{},
		}
	case NetResourceTypeEniIp:
		res = &ENIIP{
			ENI: &ENI{
				ID:        r.ENIId,
				Mac:       mac,
				PrimaryIP: IPSet{},
				Subnet:    Subnet{},
			},
			IPSet: IPSet{
				IPv4: net.ParseIP(r.IPv4),
				IPv6: net.ParseIP(r.IPv6),
			},
		}
	}
	return res
}

func GetNetResourceAllocatedFromPods(pods []*Pod) map[string]map[string]NetResourceAllocated {
	result := map[string]map[string]NetResourceAllocated{}
	for _, pod := range pods {
		for _, res := range pod.Resources {
			if result[res.Type] == nil {
				result[res.Type] = make(map[string]NetResourceAllocated)
			}
			netRes := res.ToNetResource()
			if netRes == nil {
				continue
			}
			result[res.Type][res.ID] = NetResourceAllocated{
				Owner:    PodKey(pod.Namespace, pod.Name),
				Resource: netRes,
			}
		}
	}
	return result
}

type ResStatus string

const (
	ResStatusInUse     ResStatus = "InUse"
	ResStatusAvailable ResStatus = "Available"
	ResStatusInvalid   ResStatus = "Invalid"
	ResStatusNotAdded  ResStatus = "NotAdded"
	ResStatusNormal    ResStatus = "Normal"
	ResStatusLegacy    ResStatus = "Legacy"
)

type NetResource interface {
	GetID() string
	GetType() string
	GetVPCResource() VPCResource
}

type MockNetResource struct {
	ID string
}

func (m *MockNetResource) GetID() string {
	return m.ID
}

func (m *MockNetResource) GetType() string {
	return "MockNetResource"
}

func (m *MockNetResource) GetVPCResource() VPCResource {
	return VPCResource{
		Type: m.GetType(),
		ID:   m.GetID(),
	}
}

type NetResourceAllocated struct {
	Owner    string
	Resource NetResource
}

type NetResourceStatus interface {
	NetResource
	GetStatus() ResStatus
	GetOwner() string
}

type NetResourceSnapshot struct {
	VPCResource
	Status ResStatus `json:"status"`
	Owner  string    `json:"owner,omitempty"`
}

func (m *NetResourceSnapshot) GetID() string {
	return m.ID
}

func (m *NetResourceSnapshot) GetType() string {
	return m.Type
}

func (m *NetResourceSnapshot) GetVPCResource() VPCResource {
	return m.VPCResource
}

func (m *NetResourceSnapshot) GetStatus() ResStatus {
	return m.Status
}

func (m *NetResourceSnapshot) GetOwner() string {
	return m.Owner
}

type IPFamily string

const (
	IPFamilyIPv4 = "ipv4"
	IPFamilyIPv6 = "ipv6"
	IPFamilyDual = "dual"
)

func (f IPFamily) EnableIPv4() bool {
	return f == IPFamilyIPv4 || f == IPFamilyDual
}

func (f IPFamily) EnableIPv6() bool {
	return f == IPFamilyIPv6 || f == IPFamilyDual
}

func (f IPFamily) Support(s IPFamily) bool {
	if f == IPFamilyDual {
		return true
	}
	return (s == IPFamilyIPv4 && f == IPFamilyIPv4) ||
		(s == IPFamilyIPv6 && f == IPFamilyIPv6)
}
