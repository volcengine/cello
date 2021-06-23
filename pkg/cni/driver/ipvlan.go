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
	"os"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	device2 "github.com/volcengine/cello/pkg/cni/device"
	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/cni/utils"
)

// IPVlanDriver is used in shared ENI mode.
type IPVlanDriver struct{}

// NewIPVlanDriver creates an IPVlan driver.
func NewIPVlanDriver() *IPVlanDriver {
	return &IPVlanDriver{}
}

func (d *IPVlanDriver) Name() string {
	return "ipVlan"
}

// SetupNetwork sets IPVlan data path up for netns, and also creates a fastpath (IPvlan slave interface) in host netns.
func (d *IPVlanDriver) SetupNetwork(config *types.SetupConfig) (err error) {
	// Check configs.
	if config.HostIPSet == nil {
		return fmt.Errorf("empty host IPSet")
	}
	if config.HostLink == nil {
		return fmt.Errorf("empty host link")
	}
	// 1. Create IPVlan device.
	parentENI, err := netlink.LinkByIndex(config.ENIIndex)
	if err != nil {
		err = fmt.Errorf("could not found parent device [index %d]", config.ENIIndex)
		return
	}
	if parentENI.Attrs().OperState != netlink.OperUp {
		err = netlink.LinkSetUp(parentENI)
		if err != nil {
			err = fmt.Errorf("failed to bring link %s up: %w", parentENI.Attrs().Name, err)
			return
		}
	}

	netNS, err := ns.GetNS(config.NetNSPath)
	if err != nil {
		err = fmt.Errorf("get ns handle for [%s] failed: %w", config.NetNSPath, err)
		return
	}
	defer netNS.Close()

	ipVlanConf := device2.IPVlanConf{
		MasterName: parentENI.Attrs().Name,
		IfName:     config.IfName,
		MTU:        parentENI.Attrs().MTU,
	}
	err = ipVlanConf.Setup(netNS)
	if err != nil {
		log.Log.Errorf("ipVlanConf setup error, err:%s", err.Error())
		return
	}

	defer func() {
		if err != nil {
			_ = TeardownNetwork(config.NetNSPath)
		}
	}()

	// 2. setup link
	err = netNS.Do(func(netNS ns.NetNS) error {
		podLink, inErr := netlink.LinkByName(config.IfName)
		if inErr != nil {
			return fmt.Errorf("error find link %s in container, %w", config.IfName, inErr)
		}
		linkConfig := &device2.Conf{
			IfName:    config.IfName,
			MTU:       parentENI.Attrs().MTU,
			Addresses: []*netlink.Addr{},
			Routes:    []*netlink.Route{},
			Rules:     []*netlink.Rule{},
			Neighs:    []*netlink.Neigh{},
			SysCtl:    [][]string{},
		}

		if config.BandWidth != nil && !config.BandWidth.IsZero() {
			inErr = ensureFQ(podLink) //ensure FQ for EDT bandwidth
			if inErr != nil {
				return err
			}
		}

		tableId := 0
		if config.PolicyRoute {
			tableId = utils.GetPolicyRouteTableID(podLink.Attrs().Index)
		}

		if config.IPv4 != nil {

			// Addr
			addr := &netlink.Addr{IPNet: config.IPv4}
			linkConfig.Addresses = append(linkConfig.Addresses, addr)

			// Routes.
			// To Gateway.
			linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
				Table:     tableId,
				LinkIndex: podLink.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Gw:        config.IPv4Gateway,
				Dst:       defaultIPv4Route,
				//Flags:     int(netlink.FLAG_ONLINK),
			})
			// To Host.
			if config.HostIPSet.IPv4 != nil {
				linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
					Table:     tableId,
					Dst:       netlink.NewIPNet(config.HostIPSet.IPv4),
					LinkIndex: podLink.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Src:       config.IPv4.IP,
				})
				// ARP suppression.
				linkConfig.Neighs = append(linkConfig.Neighs, &netlink.Neigh{
					LinkIndex:    podLink.Attrs().Index,
					State:        netlink.NUD_PERMANENT,
					IP:           config.HostIPSet.IPv4,
					HardwareAddr: podLink.Attrs().HardwareAddr,
				})
			}
			// Redirect To Host CIDRs.
			for _, cidr := range config.RedirectToHostCIDRs {
				if cidr.IP.To4() != nil {
					linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
						Table:     tableId,
						Dst:       cidr,
						LinkIndex: podLink.Attrs().Index,
						Scope:     netlink.SCOPE_LINK,
						Src:       config.IPv4.IP,
					})
				}
			}
			// Rules.
			if config.PolicyRoute {
				linkConfig.Rules = append(linkConfig.Rules, &netlink.Rule{
					Family:  netlink.FAMILY_V4,
					Table:   tableId,
					Src:     netlink.NewIPNet(addr.IP),
					OifName: config.IfName,
				})
			}
			// Sysctl.
			linkConfig.SysCtl = append(linkConfig.SysCtl, ipv4NetConfig...)
		}

		if config.IPv6 != nil {
			// Addr
			addr := &netlink.Addr{
				IPNet: config.IPv6,
				Flags: syscall.IFA_F_NODAD,
			}
			linkConfig.Addresses = append(linkConfig.Addresses, addr)

			// Routes.
			// To Gateway.
			linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
				Table:     tableId,
				LinkIndex: podLink.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Gw:        config.IPv6Gateway,
				Dst:       defaultIPv6Route,
				//Flags:     int(netlink.FLAG_ONLINK),
			})
			// To host.
			if config.HostIPSet.IPv6 != nil {
				linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
					Table:     tableId,
					Dst:       netlink.NewIPNet(config.HostIPSet.IPv6),
					LinkIndex: podLink.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Src:       config.IPv6.IP,
				})

				// ND suppression.
				linkConfig.Neighs = append(linkConfig.Neighs, &netlink.Neigh{
					LinkIndex:    podLink.Attrs().Index,
					State:        netlink.NUD_PERMANENT,
					IP:           config.HostIPSet.IPv6,
					HardwareAddr: podLink.Attrs().HardwareAddr,
				})
			}
			// Redirect To Host CIDRs.
			for _, cidr := range config.RedirectToHostCIDRs {
				if cidr.IP.To4() == nil {
					linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
						Table:     tableId,
						Dst:       cidr,
						LinkIndex: podLink.Attrs().Index,
						Scope:     netlink.SCOPE_LINK,
						Src:       config.IPv6.IP,
					})
				}
			}
			// Rules.
			if config.PolicyRoute {
				linkConfig.Rules = append(linkConfig.Rules, &netlink.Rule{
					Family:  netlink.FAMILY_V6,
					Table:   tableId,
					Src:     netlink.NewIPNet(addr.IP),
					OifName: config.IfName,
				})
			}

			// Sysctl
			linkConfig.SysCtl = append(linkConfig.SysCtl, ipv6NetConfig...)
		}

		config.Link = podLink
		return device2.Setup(podLink, linkConfig)

	})

	if err != nil {
		err = fmt.Errorf("setup network failed: %w", err)
		return
	}

	// 3. setup init ns
	log.Log.Infof("SetupInitNamespace")
	err = d.setupInitNamespace(config)
	if err != nil {
		log.Log.Errorf("SetupInitNamespace failed, err:%s", err.Error())
		return err
	}
	return
}

func (d *IPVlanDriver) setupInitNamespace(cfg *types.SetupConfig) error {
	parentLink, err := netlink.LinkByIndex(cfg.ENIIndex)
	if err != nil {
		return fmt.Errorf("error get eni by index %d, %w", cfg.ENIIndex, err)
	}

	// 1.1 ensure initSlave device
	initSlaveName := fmt.Sprintf("ipvl_%d", parentLink.Attrs().Index)
	initSlaveLink, err := d.createIPVlanSlave(parentLink, initSlaveName)
	if err != nil {
		return fmt.Errorf("ensure init slave device failed: %s", err.Error())
	}

	if initSlaveLink.Attrs().Flags&unix.IFF_NOARP == 0 {
		if err := netlink.LinkSetARPOff(initSlaveLink); err != nil {
			return fmt.Errorf("set device %s noarp error, %w", initSlaveLink.Attrs().Name, err)
		}
	}

	if initSlaveLink.Attrs().OperState != netlink.OperUp {
		err := netlink.LinkSetUp(initSlaveLink)
		if err != nil {
			return fmt.Errorf("failed to bring link %s up: %w", initSlaveLink.Attrs().Name, err)
		}
	}

	// 1.2 ensure addr
	if cfg.HostIPSet.IPv4 != nil {
		err = netlink.AddrReplace(initSlaveLink, &netlink.Addr{IPNet: netlink.NewIPNet(cfg.HostIPSet.IPv4)})
		if err != nil {
			return err
		}
	}
	if cfg.HostIPSet.IPv6 != nil {
		err := netlink.AddrReplace(initSlaveLink, &netlink.Addr{IPNet: netlink.NewIPNet(cfg.HostIPSet.IPv6)})
		if err != nil {
			return err
		}
	}
	// 2. ensure tc for ipvlan dataPath (nodePort and nodeLocalDns)
	var srcEgressRedirectCIDRs []*net.IPNet
	if cfg.HostIPSet.IPv4 != nil {
		srcEgressRedirectCIDRs = append(srcEgressRedirectCIDRs, netlink.NewIPNet(cfg.HostIPSet.IPv4))
	}
	if cfg.HostIPSet.IPv6 != nil {
		srcEgressRedirectCIDRs = append(srcEgressRedirectCIDRs, netlink.NewIPNet(cfg.HostIPSet.IPv6))
	}
	err = d.setupFilters(parentLink, srcEgressRedirectCIDRs, cfg.HostLink.Attrs().Index,
		cfg.RedirectToHostCIDRs, initSlaveLink.Attrs().Index)
	if err != nil {
		return fmt.Errorf("setup filters failed: %s", err.Error())
	}

	// 3. add fast path to local pod
	if cfg.IPv4 != nil {
		v4route := &netlink.Route{
			LinkIndex: initSlaveLink.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       netlink.NewIPNet(cfg.IPv4.IP),
			Family:    netlink.FAMILY_V4,
		}
		err = netlink.RouteReplace(v4route)
		if err != nil {
			return fmt.Errorf("add ipv4 fast path to pod failed: %s", err.Error())
		}
	}
	if cfg.IPv6 != nil {
		v6route := &netlink.Route{
			LinkIndex: initSlaveLink.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       netlink.NewIPNet(cfg.IPv6.IP),
			Family:    netlink.FAMILY_V6,
		}
		err = netlink.RouteReplace(v6route)
		if err != nil {
			return fmt.Errorf("add ipv6 fast path to pod failed %s", err.Error())
		}
	}

	return nil
}

func (d *IPVlanDriver) setupFilters(link netlink.Link, srcEgressRedirectCIDRs []*net.IPNet, egressIndex int,
	dstIngressRedirectCIDRs []*net.IPNet, ingressIndex int) error {
	err := ensureClsActQdsic(link)
	if err != nil {
		return fmt.Errorf("ensureClsActQdsic failed: %s", err.Error())
	}

	ruleInFilter := make(map[*redirectRule]bool)
	for _, cidr := range srcEgressRedirectCIDRs {
		rule, err := generateSrcRedirRule(link.Attrs().Index, cidr, egressIndex, netlink.TCA_EGRESS_REDIR)
		if err != nil {
			return fmt.Errorf("create egress redirect rule error, %w", err)
		}
		ruleInFilter[rule] = false
	}

	for _, cidr := range dstIngressRedirectCIDRs {
		rule, err := gernerateDstRedirRule(link.Attrs().Index, cidr, ingressIndex, netlink.TCA_INGRESS_REDIR)
		if err != nil {
			return fmt.Errorf("create ingress redirect rule error, %w", err)
		}
		ruleInFilter[rule] = false
	}

	parent := uint32(netlink.HANDLE_CLSACT&0xffff0000 | netlink.HANDLE_MIN_EGRESS&0x0000ffff)
	if err != nil {
		return fmt.Errorf("list egress filter for %s error, %w", link.Attrs().Name, err)
	}

	filtersToDeleted := make([]netlink.Filter, 0)
	filters, err := netlink.FilterList(link, parent)
	log.Log.Errorf("failed to get filter list, %v", err)
	for _, filter := range filters {
		matchAny := false
		for rule := range ruleInFilter {
			if rule.isMatch(filter) {
				ruleInFilter[rule] = true
				matchAny = true
				// Should match only one rule, duplicated filters will be deleted.
				delete(ruleInFilter, rule)
				break
			}
		}
		if !matchAny {
			filtersToDeleted = append(filtersToDeleted, filter)
		}
	}

	// Delete redundant and legacy(u32) filters.
	for _, filter := range filtersToDeleted {
		if err := netlink.FilterDel(filter); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete filter of %s error, %w", link.Attrs().Name, err)
		}
	}

	for rule, in := range ruleInFilter {
		if !in {
			filter := rule.toFlower()
			filter.Parent = parent
			if err := netlink.FilterReplace(filter); err != nil && !os.IsExist(err) {
				return fmt.Errorf("add filter for %s error, %w", link.Attrs().Name, err)
			}
		}
	}
	return nil
}

func (d *IPVlanDriver) createIPVlanSlave(parentLink netlink.Link, slaveName string) (netlink.Link, error) {
	slaveLink, err := netlink.LinkByName(slaveName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return nil, fmt.Errorf("get device %s error, %w", slaveName, err)
		}
	} else {
		log.Log.Infof("Slave interface has existed.")
		return slaveLink, nil
	}

	// create one
	err = netlink.LinkAdd(&netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        slaveName,
			ParentIndex: parentLink.Attrs().Index,
			MTU:         parentLink.Attrs().MTU,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	})
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		log.Log.Infof("Slave interface create failed.")
		return nil, err
	}
	link, err := netlink.LinkByName(slaveName)
	if err != nil {
		return nil, fmt.Errorf("error get ipvlan link %s", slaveName)
	}
	log.Log.Infof("Create slave device %s in host netns success", slaveName)
	return link, nil
}

// generateSrcRedirRule generates a rule to redirect to primary interface packet which src ip address equals the host.
func generateSrcRedirRule(index int, ip *net.IPNet, dstIfIndex int, redir netlink.MirredAct) (*redirectRule, error) {
	if ip == nil {
		return nil, fmt.Errorf("src is nil")
	}
	proto := uint16(unix.ETH_P_IP)
	if ip.IP.To4() == nil {
		proto = unix.ETH_P_IPV6
	}

	mirredAct := netlink.NewMirredAction(dstIfIndex)
	mirredAct.MirredAction = redir

	return &redirectRule{
		linkIndex:    index,
		proto:        proto,
		matchIP:      *ip,
		isSrcIngress: true,
		acts:         []netlink.Action{mirredAct},
	}, nil
}

// gernerateDstRedirRule generates a rule which redirect packet with specified dst ip to primary interface
func gernerateDstRedirRule(index int, ip *net.IPNet, dstIfIndex int, redir netlink.MirredAct) (*redirectRule, error) {
	if ip == nil {
		return nil, fmt.Errorf("dst is nil")
	}

	proto := uint16(unix.ETH_P_IP)
	if ip.IP.To4() == nil {
		proto = unix.ETH_P_IPV6
	}

	var actions []netlink.Action

	skbedit := netlink.NewSkbEditAction()
	ptype := uint16(unix.PACKET_HOST)
	skbedit.PType = &ptype

	mirredAct := netlink.NewMirredAction(dstIfIndex)
	mirredAct.MirredAction = redir

	actions = append(actions, skbedit, mirredAct)
	return &redirectRule{
		linkIndex:    index,
		proto:        proto,
		matchIP:      *ip,
		isSrcIngress: false,
		acts:         actions,
	}, nil
}
