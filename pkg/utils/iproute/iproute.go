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

package iproute

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	k8snet "k8s.io/apimachinery/pkg/util/net"

	"github.com/volcengine/cello/types"
)

// NetlinkFamily return family of ip.
func NetlinkFamily(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

// FoundRoutes lookup expected Routes.
func FoundRoutes(expected *netlink.Route) ([]netlink.Route, error) {
	var family int
	if expected.Dst != nil {
		family = NetlinkFamily(expected.Dst.IP)
	} else {
		family = NetlinkFamily(expected.Gw)
	}
	routeFilter := netlink.RT_FILTER_DST
	if expected.Dst == nil {
		return nil, fmt.Errorf("dst in route expect not nil")
	}
	find := *expected

	if find.Dst.String() == "::/0" || find.Dst.String() == "0.0.0.0/0" {
		find.Dst = nil
	}
	if find.LinkIndex > 0 {
		routeFilter |= netlink.RT_FILTER_OIF
	}
	if find.Scope > 0 {
		routeFilter |= netlink.RT_FILTER_SCOPE
	}
	if find.Gw != nil {
		routeFilter |= netlink.RT_FILTER_GW
	}
	if find.Table > 0 {
		routeFilter |= netlink.RT_FILTER_TABLE
	}
	return netlink.RouteListFiltered(family, &find, routeFilter)
}

// FindIPRule lookup expected rules.
func FindIPRule(rule *netlink.Rule) ([]netlink.Rule, error) {
	var filterMask uint64
	family := netlink.FAMILY_V4

	if rule.Src == nil && rule.Dst == nil && rule.OifName == "" {
		return nil, fmt.Errorf("both src and dst is nil")
	}

	if rule.Src != nil {
		filterMask |= netlink.RT_FILTER_SRC
		family = NetlinkFamily(rule.Src.IP)
	}
	if rule.Dst != nil {
		filterMask |= netlink.RT_FILTER_DST
		family = NetlinkFamily(rule.Dst.IP)
	}
	if rule.OifName != "" {
		filterMask |= netlink.RT_FILTER_OIF
		family = netlink.FAMILY_V4
	}

	if rule.Priority >= 0 {
		filterMask |= netlink.RT_FILTER_PRIORITY
	}
	return netlink.RuleListFiltered(family, rule, filterMask)
}

// GetHostIP return types.IPSet of Host.
func GetHostIP() (*types.IPSet, error) {
	var ipSet types.IPSet
	var err error
	hostIPv4, v4Err := k8snet.ResolveBindAddress(net.ParseIP("127.0.0.1"))
	hostIPv6, v6Err := k8snet.ResolveBindAddress(net.ParseIP("::1"))
	if v4Err == nil {
		hostIPv4 = hostIPv4.To4()
	}

	if v6Err == nil && hostIPv6.To4() != nil {
		hostIPv6 = nil
	}

	ipSet.IPv4 = hostIPv4
	ipSet.IPv6 = hostIPv6

	if v4Err == nil && v6Err == nil {
		err = nil
	} else {
		err = fmt.Errorf("%v, %v", v4Err, v6Err)
	}
	return &ipSet, err
}

// GetLinkAddresses return ips of specified link.
func GetLinkAddresses(link netlink.Link) ([]netlink.Addr, error) {
	Addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("get link addrs(of %s) failed: %s", link.Attrs().Name, err.Error())
	}
	return Addrs, nil
}

// EnsureNeigh add specified neigh if it not exists.
func EnsureNeigh(neigh *netlink.Neigh) error {
	var neighs []netlink.Neigh
	var err error
	if NetlinkFamily(neigh.IP) == netlink.FAMILY_V6 {
		neighs, err = netlink.NeighList(neigh.LinkIndex, netlink.FAMILY_V6)
	} else {
		neighs, err = netlink.NeighList(neigh.LinkIndex, netlink.FAMILY_V4)
	}
	if err != nil {
		return err
	}
	found := false
	for _, n := range neighs {
		if n.IP.Equal(neigh.IP) && n.HardwareAddr.String() == neigh.HardwareAddr.String() {
			found = true
			break
		}
	}
	if !found {
		return netlink.NeighSet(neigh)
	}
	return err
}

// EnsureRoute add specified route if it not exists.
func EnsureRoute(expected *netlink.Route) error {
	routes, err := FoundRoutes(expected)
	if err != nil {
		return fmt.Errorf("find expected routes failed: %w", err)
	}
	if len(routes) > 0 {
		return nil
	}

	return netlink.RouteReplace(expected)
}

// EnsureIPRule add specified rule if it not exists.
func EnsureIPRule(expected *netlink.Rule) error {
	ruleList, err := FindIPRule(expected)
	if err != nil {
		return err
	}
	found := false
	for i, rule := range ruleList {
		del := false
		if rule.Table != expected.Table {
			del = true
		}
		if rule.Priority != expected.Priority {
			del = true
		}
		if rule.IifName != expected.IifName {
			del = true
		}
		if del {
			err = netlink.RuleDel(&ruleList[i])
			if err != nil {
				return err
			}
		} else {
			found = true
		}
	}
	if found {
		return nil
	}
	return netlink.RuleAdd(expected)
}

// LinkByMac get link by mac, it will ignore virtual nic type.
func LinkByMac(mac string) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list link failed: %w", err)
	}
	for _, link := range links {
		// ignore virtual nic type. eg. ipvlan veth bridge
		if _, ok := link.(*netlink.Device); !ok {
			continue
		}
		if link.Attrs().HardwareAddr.String() == mac {
			return link, nil
		}
	}
	return nil, fmt.Errorf("no link found by mac %s", mac)
}

// GetDefaultRoute get the default route of the corresponding family.
func GetDefaultRoute(family int) (*netlink.Route, error) {
	if family != netlink.FAMILY_ALL && family != netlink.FAMILY_V4 && family != netlink.FAMILY_V6 {
		return nil, fmt.Errorf("family must be FAMILY_V6 or FAMILY_V4")
	}

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{}, netlink.RT_FILTER_DST)
	if err != nil || len(routes) == 0 {
		return nil, fmt.Errorf("default route not found")
	}

	return &routes[0], nil
}

// GetHostLinkByDefaultRoute get the link pointed to by the default route.
func GetHostLinkByDefaultRoute(family int) (netlink.Link, error) {
	route, err := GetDefaultRoute(family)
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return nil, err
	}
	return link, nil
}
