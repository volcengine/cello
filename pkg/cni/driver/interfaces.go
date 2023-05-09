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

package driver

import (
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/iproute"
)

const (
	defaultVethForContainer     = "veth1"
	defaultFlowerFilterPriority = uint16(40000)
)

var (
	ipv4NetConfig = [][]string{
		{"net/ipv4/conf/%s/arp_notify", "1"},
	}

	ipv6NetConfig = [][]string{
		{"net/ipv6/conf/%s/disable_ipv6", "0"},
	}

	_, defaultIPv4Route, _ = net.ParseCIDR("0.0.0.0/0")
	_, defaultIPv6Route, _ = net.ParseCIDR("::/0")
)

// DataPath is data path driver interface.
type DataPath interface {
	Name() string
	// SetupNetwork will set up datapath for netns.
	SetupNetwork(config *types.SetupConfig) error
}

// FastPath is the local fastpath between pods and host.
type FastPath struct {
	dst   []netlink.Addr
	table int
}

// SetupDataPath setup data path for netns according to DP mode.
func SetupDataPath(setupConfig *types.SetupConfig) error {
	var dataPathDriver DataPath
	switch setupConfig.DP {
	case types.IPVlan:
		dataPathDriver = NewIPVlanDriver()
	case types.ENI:
		dataPathDriver = NewExclusiveENIDriver()
	case types.Vlan:
		dataPathDriver = NewVlanDriver()
	default:
		return fmt.Errorf("unsupport datapath %d", setupConfig.DP)
	}
	log.Log.Infof("DataPath driver %s setup network, %s", dataPathDriver.Name(), setupConfig.String())
	return dataPathDriver.SetupNetwork(setupConfig)
}

// TeardownNetwork all the networks netns.
func TeardownNetwork(netNs string) error {
	if netNs == "" {
		return nil
	}
	containerNs, err := ns.GetNS(netNs)
	if err != nil {
		log.Log.Infof("Target netns doesn't exist.")
		return nil
	}
	defer func(containerNs ns.NetNS) {
		err := containerNs.Close()
		if err != nil {
			log.Log.Errorf("Failed to close netns due to: %v", err.Error())
		}
	}(containerNs)
	var fastPaths []*FastPath
	err = containerNs.Do(func(netNS ns.NetNS) error {
		links, err2 := netlink.LinkList()
		if err2 != nil {
			return fmt.Errorf("list links failed: %w", err2)
		}
		for _, link := range links {
			switch link.(type) {
			case *netlink.IPVlan:
				ip, inErr := netlink.AddrList(link, netlink.FAMILY_ALL)
				if inErr != nil {
					return fmt.Errorf("list addresses for link %s failed: %w", link.Attrs().Name, inErr)
				}
				fastPaths = append(fastPaths, &FastPath{
					dst:   ip,
					table: 0,
				})
				inErr = netlink.LinkDel(link)
				if inErr != nil {
					log.Log.Warnf("Delete link %s failed: %s", link.Attrs().Name, inErr)
				}
			case *netlink.Veth:
				inErr := netlink.LinkDel(link)
				if inErr != nil {
					log.Log.Warnf("Delete link %s failed: %s", link.Attrs().Name, inErr)
				}
			case *netlink.Vlan:
				inErr := netlink.LinkDel(link)
				if inErr != nil {
					log.Log.Warnf("Delete link %s failed: %s", link.Attrs().Name, inErr)
				}
			default:
				addresses, inErr := netlink.AddrList(link, netlink.FAMILY_ALL)
				if inErr != nil {
					return fmt.Errorf("list addresses for link %s failed: %w", link.Attrs().Name, inErr)
				}
				for i, address := range addresses {
					inErr = netlink.AddrDel(link, &addresses[i])
					if inErr != nil {
						return fmt.Errorf("remove address %s from link %s failed: %s", address.String(), link.Attrs().Name, inErr)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Log.Errorf("failed to cleanup container network: %v", err)
	}

	// Cleanup fast path.
	for _, fastPath := range fastPaths {
		for _, addr := range fastPath.dst {
			err = teardownFastPathCfg(addr.IPNet, fastPath.table)
			if err != nil {
				log.Log.Warnf("TeardownFastPathCfg[dst: %s, table: %d] failed, %s", addr.IP.String(), fastPath.table, err.Error())
			}
		}
	}
	return nil
}

func teardownFastPathCfg(containerIP *net.IPNet, tableId int) error {
	if containerIP == nil {
		return nil
	}
	// del fast route to pod
	deleteRoute := func(ipNet *net.IPNet) error {
		routes, err := iproute.FoundRoutes(&netlink.Route{
			Table: tableId,
			Dst:   ipNet,
		})
		if err != nil {
			return err
		}
		for i := range routes {
			err = netlink.RouteDel(&routes[i])
			if err != nil {
				return err
			}
		}
		return nil
	}
	err := deleteRoute(netlink.NewIPNet(containerIP.IP))
	if err != nil {
		return err
	}
	return nil
}

type redirectRule struct {
	linkIndex    int
	proto        uint16
	matchIP      net.IPNet
	acts         []netlink.Action
	isSrcIngress bool
}

func (rule *redirectRule) isMatchActions(acts []netlink.Action) bool {
	if len(rule.acts) != len(acts) {
		return false
	}
	for i, act := range acts {
		if act.Type() != rule.acts[i].Type() {
			return false
		}
		switch act.(type) {
		case *netlink.TunnelKeyAction:
			tun1 := act.(*netlink.TunnelKeyAction)
			tun2 := rule.acts[i].(*netlink.TunnelKeyAction)
			if tun1.Attrs().Action != tun2.Attrs().Action {
				return false
			}
			if tun1.Action != tun2.Action {
				return false
			}
		case *netlink.SkbEditAction:
			edit1 := act.(*netlink.SkbEditAction)
			edit2 := rule.acts[i].(*netlink.SkbEditAction)
			if edit1.Attrs().Action != edit2.Attrs().Action {
				return false
			}
			if datatype.Uint16Value(edit1.PType) != datatype.Uint16Value(edit2.PType) {
				return false
			}
		case *netlink.MirredAction:
			mir1 := act.(*netlink.MirredAction)
			mir2 := rule.acts[i].(*netlink.MirredAction)
			if mir1.Attrs().Action != mir2.Attrs().Action {
				return false
			}
			if mir1.MirredAction != mir2.MirredAction {
				return false
			}
			if mir1.Ifindex != mir2.Ifindex {
				return false
			}
		case *netlink.VlanAction:
			v1 := act.(*netlink.VlanAction)
			v2 := rule.acts[i].(*netlink.VlanAction)
			if v1.Attrs().Action != v2.Attrs().Action {
				return false
			}
			if v1.Action != v2.Action {
				return false
			}
			if v1.Vid != v2.Vid {
				return false
			}
			if v1.Prio != v2.Prio {
				return false
			}
			if v1.Proto != v2.Proto {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (rule *redirectRule) isMatch(filter netlink.Filter) bool {
	flower, ok := filter.(*netlink.Flower)
	if !ok {
		return false
	}
	if flower.Attrs().LinkIndex != rule.linkIndex || flower.Attrs().Protocol != rule.proto {
		return false
	}
	if rule.isSrcIngress {
		return rule.matchIP.Contains(flower.SrcIP) && rule.isMatchActions(flower.Actions)
	}

	return rule.matchIP.Contains(flower.DestIP) && rule.isMatchActions(flower.Actions)
}

func (rule *redirectRule) toFlower() *netlink.Flower {
	var src net.IP
	var dst net.IP
	var srcMask net.IPMask
	var dstMask net.IPMask
	priority := defaultFlowerFilterPriority
	if rule.matchIP.IP.To4() == nil {
		priority++
	}
	if rule.isSrcIngress {
		src = rule.matchIP.IP
		srcMask = rule.matchIP.Mask
	} else {
		dst = rule.matchIP.IP
		dstMask = rule.matchIP.Mask
	}

	return &netlink.Flower{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: rule.linkIndex,
			Priority:  priority,
			Protocol:  rule.proto,
		},
		DestIP:     dst,
		DestIPMask: dstMask,
		SrcIP:      src,
		SrcIPMask:  srcMask,
		EthType:    rule.proto,
		Actions:    rule.acts,
	}
}

func ensureClsActQdsic(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			return nil
		}
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.HANDLE_CLSACT & 0xffff0000,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return fmt.Errorf("replace clsact qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	return nil
}

func ensureFQ(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdisc for dev %s error, %w", link.Attrs().Name, err)
	}

	for _, qdisc := range qdiscs {
		if qdisc.Type() == "fq" &&
			qdisc.Attrs().Parent == netlink.HANDLE_ROOT &&
			qdisc.Attrs().Handle == netlink.MakeHandle(1, 0) {
			return nil
		}
	}

	fq := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
			Handle:    netlink.MakeHandle(1, 0),
		},
		QdiscType: "fq",
	}
	err = netlink.QdiscReplace(fq)
	if err != nil {
		return fmt.Errorf("failed to ensure FQ for devices Index:%v due to: %v",
			link.Attrs().Index, err)
	}
	return nil
}
