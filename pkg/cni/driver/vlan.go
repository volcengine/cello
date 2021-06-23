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
	"os"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	device2 "github.com/volcengine/cello/pkg/cni/device"
	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/cni/utils"
	"github.com/volcengine/cello/pkg/utils/iproute"
	celloTypes "github.com/volcengine/cello/types"
)

type VlanDriver struct{}

// NewVlanDriver creates vlan driver.
func NewVlanDriver() *VlanDriver {
	return &VlanDriver{}
}

// Name will return the name of Vlan driver.
func (d *VlanDriver) Name() string {
	return "vlan"
}

// SetupNetwork sets vlan data path up.
func (d *VlanDriver) SetupNetwork(cfg *types.SetupConfig) (err error) {
	// 1. create an vlan device
	parentENI, err := netlink.LinkByIndex(cfg.ENIIndex)
	if err != nil {
		return fmt.Errorf("could not found parent device [index %d]", cfg.ENIIndex)
	}
	if parentENI.Attrs().OperState != netlink.OperUp {
		err = netlink.LinkSetUp(parentENI)
		if err != nil {
			return fmt.Errorf("failed to bring link %s up: %w", parentENI.Attrs().Name, err)
		}
	}
	hostNetNS, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("err get host net ns, %w", err)
	}

	netNs, err := ns.GetNS(cfg.NetNSPath)
	if err != nil {
		return fmt.Errorf("get netNs [%s] failed: %w", cfg.NetNSPath, err)
	}
	defer netNs.Close()

	vlanCfg := &device2.VlanConfig{
		IfName:       cfg.IfName,
		MasterName:   parentENI.Attrs().Name,
		Vid:          int(cfg.Vid),
		MTU:          parentENI.Attrs().MTU,
		HardwareAddr: cfg.HardwareAddr,
	}
	err = vlanCfg.Setup(netNs)
	if err != nil {
		return fmt.Errorf("setup vlan device error, %s", err.Error())
	}

	setVeth := cfg.IfName == celloTypes.DefaultIfName && (cfg.LocalFastPath || len(cfg.RedirectToHostCIDRs) != 0)

	// 2. setup device in container ns
	err = netNs.Do(func(_ ns.NetNS) error {
		podLink, inErr := netlink.LinkByName(cfg.IfName)
		if inErr != nil {
			return fmt.Errorf("find link %s in container err, %s", cfg.IfName, inErr.Error())
		}
		cfg.Link = podLink
		containerConf, inErr := generateVlanConf(cfg, podLink)
		if inErr != nil {
			return inErr
		}
		inErr = device2.Setup(podLink, containerConf)
		if inErr != nil {
			return inErr
		}
		inErr = ensureFQ(podLink)
		if inErr != nil {
			return inErr
		}

		if setVeth {
			veth := &device2.VethConf{
				IfName:   cfg.VethNameInHost,
				PeerName: defaultVethForContainer,
			}
			inErr = veth.Setup(hostNetNS)
			if inErr != nil {
				return fmt.Errorf("setup veth pair error, %s", inErr.Error())
			}

			veth1, inErr := netlink.LinkByName(defaultVethForContainer)
			if inErr != nil {
				return inErr
			}
			vethConf, inErr := generateVethConf(cfg, veth1)
			if inErr != nil {
				return inErr
			}
			return device2.Setup(veth1, vethConf)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("setup network error, %s", err.Error())
	}
	log.Log.Infof("Container ns setup success")
	// 3. fast path to pod
	tableId := utils.GetPolicyRouteTableID(cfg.HostLink.Attrs().Index)
	if cfg.LocalFastPath {
		tableId = 0
	}
	if setVeth {
		var vethLink netlink.Link
		vethLink, err = netlink.LinkByName(cfg.VethNameInHost)
		if err != nil {
			return fmt.Errorf("find veth link for fast path failed, %s", err.Error())
		}
		vethConf := &device2.Conf{}
		if cfg.IPv4 != nil {
			vethConf.Routes = append(vethConf.Routes, &netlink.Route{
				Table:     tableId,
				LinkIndex: vethLink.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       netlink.NewIPNet(cfg.IPv4.IP),
			})
		}
		if cfg.IPv6 != nil {
			vethConf.Routes = append(vethConf.Routes, &netlink.Route{
				Table:     tableId,
				LinkIndex: vethLink.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       netlink.NewIPNet(cfg.IPv6.IP),
			})
		}
		err = device2.Setup(vethLink, vethConf)
		if err != nil {
			return fmt.Errorf("setup veth link %s in host ns failed, %s", vethLink.Attrs().Name, err.Error())
		}
	}
	log.Log.Infof("Setup veth in host ns success")

	if !cfg.LocalFastPath {
		for _, c := range cfg.RedirectToHostCIDRs {
			rule := netlink.NewRule()
			rule.Family = iproute.NetlinkFamily(c.IP)
			rule.Table = tableId
			rule.Src = c
			err = iproute.EnsureIPRule(rule)
			if err != nil {
				return fmt.Errorf("ensure rule failed, %s", err.Error())
			}
		}
	}
	log.Log.Infof("Setup filters")
	// 4. check tc in parent device
	return d.setupFilters(cfg, parentENI)
}

func generateVethConf(cfg *types.SetupConfig, link netlink.Link) (*device2.Conf, error) {
	var addrs []*netlink.Addr
	var routes []*netlink.Route

	if cfg.IPv4 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: netlink.NewIPNet(cfg.IPv4.IP)})
		if cfg.LocalFastPath && cfg.HostIPSet.IPv4 != nil {
			routes = append(routes, &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       netlink.NewIPNet(cfg.HostIPSet.IPv4),
			})
		}
	}

	if cfg.IPv6 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: netlink.NewIPNet(cfg.IPv6.IP)})
		if cfg.LocalFastPath && cfg.HostIPSet.IPv6 != nil {
			routes = append(routes, &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       netlink.NewIPNet(cfg.HostIPSet.IPv6),
			})
		}
	}

	for _, cidr := range cfg.RedirectToHostCIDRs {
		routes = append(routes, &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       cidr,
		})
	}
	return &device2.Conf{
		IfName:    defaultVethForContainer,
		Addresses: addrs,
		Routes:    routes,
	}, nil
}

func (d *VlanDriver) setupFilters(cfg *types.SetupConfig, link netlink.Link) error {
	err := ensureClsActQdsic(link)
	if err != nil {
		return fmt.Errorf("ensureClsActQdsic failed: %s", err.Error())
	}
	parent := uint32(netlink.HANDLE_CLSACT&0xffff0000 | netlink.HANDLE_MIN_EGRESS&0x0000ffff)
	pop := netlink.NewVlanKeyAction()
	pop.Attrs().Action = netlink.TC_ACT_PIPE
	pop.Action = netlink.TCA_VLAN_KEY_POP

	mirredAct := netlink.NewMirredAction(cfg.HostLink.Attrs().Index)
	mirredAct.MirredAction = netlink.TCA_EGRESS_REDIR

	expectRulesInFilter := make(map[*redirectRule]bool)

	if cfg.IPv4 != nil && cfg.HostIPSet.IPv4 != nil {
		expectRulesInFilter[&redirectRule{
			linkIndex:    link.Attrs().Index,
			proto:        unix.ETH_P_IP,
			isSrcIngress: true,
			matchIP:      *netlink.NewIPNet(cfg.HostIPSet.IPv4),
			acts:         []netlink.Action{pop, mirredAct},
		}] = false
	}

	if cfg.IPv6 != nil && cfg.HostIPSet.IPv6 != nil {
		expectRulesInFilter[&redirectRule{
			linkIndex:    link.Attrs().Index,
			proto:        unix.ETH_P_IPV6,
			isSrcIngress: true,
			matchIP:      *netlink.NewIPNet(cfg.HostIPSet.IPv6),
			acts:         []netlink.Action{pop, mirredAct},
		}] = false
	}

	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return fmt.Errorf("list egress filter for %s error, %w", link.Attrs().Name, err)
	}

	for _, filter := range filters {
		matchAny := false
		for rule := range expectRulesInFilter {
			if rule.isMatch(filter) {
				expectRulesInFilter[rule] = true
				matchAny = true
				break
			}
		}
		if matchAny {
			continue
		}
		if err := netlink.FilterDel(filter); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete filter of %s error, %w", link.Attrs().Name, err)
		}
	}

	for rule, in := range expectRulesInFilter {
		if !in {
			flower := rule.toFlower()
			flower.Parent = parent
			if err := netlink.FilterAdd(flower); err != nil {
				return fmt.Errorf("add filter for %s error, %w", link.Attrs().Name, err)
			}
		}
	}
	return nil
}

func generateVlanConf(cfg *types.SetupConfig, link netlink.Link) (*device2.Conf, error) {
	linkConfig := &device2.Conf{
		IfName:    cfg.IfName,
		Addresses: []*netlink.Addr{},
		Routes:    []*netlink.Route{},
		Rules:     []*netlink.Rule{},
		Neighs:    []*netlink.Neigh{},
		SysCtl:    [][]string{},
	}

	tableId := 0
	if cfg.PolicyRoute {
		tableId = utils.GetPolicyRouteTableID(link.Attrs().Index)
	}

	if cfg.IPv4 != nil {
		// Addr
		addr := &netlink.Addr{IPNet: cfg.IPv4}
		linkConfig.Addresses = append(linkConfig.Addresses, addr)

		// Route
		// default
		linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
			Table:     tableId,
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Gw:        cfg.IPv4Gateway,
			Dst:       defaultIPv4Route,
			Flags:     int(netlink.FLAG_ONLINK),
		})

		// Rules
		if cfg.PolicyRoute {
			linkConfig.Rules = append(linkConfig.Rules, &netlink.Rule{
				Family:  netlink.FAMILY_V4,
				Table:   tableId,
				Src:     netlink.NewIPNet(addr.IP),
				OifName: cfg.IfName,
			})
		}
	}

	if cfg.IPv6 != nil {
		// Addr
		addr := &netlink.Addr{
			IPNet: cfg.IPv6,
			Flags: syscall.IFA_F_NODAD,
		}
		linkConfig.Addresses = append(linkConfig.Addresses, addr)

		// Route
		// default
		linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
			Table:     tableId,
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Gw:        cfg.IPv6Gateway,
			Dst:       defaultIPv6Route,
			Flags:     int(netlink.FLAG_ONLINK),
		})

		// Rules
		if cfg.PolicyRoute {
			linkConfig.Rules = append(linkConfig.Rules, &netlink.Rule{
				Family:  netlink.FAMILY_V6,
				Table:   tableId,
				Src:     netlink.NewIPNet(addr.IP),
				OifName: cfg.IfName,
			})
		}

		// Sysctl
		linkConfig.SysCtl = append(linkConfig.SysCtl, ipv6NetConfig...)
	}
	return linkConfig, nil
}
