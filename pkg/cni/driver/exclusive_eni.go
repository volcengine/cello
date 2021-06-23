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
	"syscall"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/cni/device"
	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/cni/utils"
)

type ExclusiveENI struct{}

func NewExclusiveENIDriver() *ExclusiveENI {
	return &ExclusiveENI{}
}

func (d *ExclusiveENI) Name() string {
	return "exclusiveENI"
}

func (d *ExclusiveENI) SetupNetwork(config *types.SetupConfig) (err error) {
	targetENI, err := netlink.LinkByIndex(config.ENIIndex)
	if err != nil {
		err = fmt.Errorf("could not found parent device [index %d]", config.ENIIndex)
		return
	}
	if targetENI.Attrs().OperState != netlink.LinkOperState(netlink.OperUp) {
		err = netlink.LinkSetUp(targetENI)
		if err != nil {
			return fmt.Errorf("failed to set link up due to: %v", err.Error())
		}
	}
	config.Link = targetENI

	// setup device in pod ns
	var netns ns.NetNS
	netns, err = ns.GetNS(config.NetNSPath)
	if err != nil {
		err = fmt.Errorf("get ns handle for [%s] failed: %w", config.NetNSPath, err)
		return
	}
	defer netns.Close()
	err = netlink.LinkSetNsFd(targetENI, int(netns.Fd()))
	if err != nil {
		err = fmt.Errorf("set link %s to netns failed: %w", targetENI.Attrs().Name, err)
		return
	}

	defer func() {
		if err != nil {
			_ = TeardownNetwork(config.NetNSPath)
		}
	}()

	err = netns.Do(func(netNS ns.NetNS) error {
		linkConfig := &device.Conf{
			IfName:    config.IfName,
			MTU:       targetENI.Attrs().MTU,
			Addresses: []*netlink.Addr{},
			Routes:    []*netlink.Route{},
			Rules:     []*netlink.Rule{},
			Neighs:    []*netlink.Neigh{},
			SysCtl:    [][]string{},
		}
		podLink, err2 := netlink.LinkByIndex(targetENI.Attrs().Index)
		if err2 != nil {
			return fmt.Errorf("could not find interface %d inside netns after name changed", targetENI.Attrs().Index)
		}

		if config.BandWidth != nil && !config.BandWidth.IsZero() {
			err = ensureFQ(podLink)
			if err != nil {
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

			// Route
			linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
				Table:     tableId,
				LinkIndex: podLink.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       defaultIPv4Route,
				Gw:        config.IPv4Gateway,
				//Flags:     int(netlink.FLAG_ONLINK),
			})

			// Rules
			if config.PolicyRoute {
				linkConfig.Rules = append(linkConfig.Rules, &netlink.Rule{
					Family:  netlink.FAMILY_V4,
					Table:   tableId,
					Src:     netlink.NewIPNet(addr.IP),
					OifName: podLink.Attrs().Name,
				})
			}
		}

		if config.IPv6 != nil {
			// Addr
			addr := &netlink.Addr{IPNet: config.IPv6,
				Flags: syscall.IFA_F_NODAD,
			}
			linkConfig.Addresses = append(linkConfig.Addresses, addr)

			// Route
			linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
				Table:     tableId,
				LinkIndex: podLink.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Gw:        config.IPv6Gateway,
				Dst:       defaultIPv6Route,
				//Flags:     int(netlink.FLAG_ONLINK),
			})

			// Rules
			if config.PolicyRoute {
				linkConfig.Rules = append(linkConfig.Rules, &netlink.Rule{
					Family:  netlink.FAMILY_V6,
					Table:   tableId,
					Src:     netlink.NewIPNet(addr.IP),
					OifName: podLink.Attrs().Name,
				})
			}

			// Sysctl
			linkConfig.SysCtl = append(linkConfig.SysCtl, ipv6NetConfig...)
		}

		return device.Setup(podLink, linkConfig)
	})

	if err != nil {
		err = fmt.Errorf("setup network failed: %w", err)
		return
	}

	return
}
