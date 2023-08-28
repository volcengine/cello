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

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/plugins/device"
	"github.com/volcengine/cello/pkg/plugins/log"
	"github.com/volcengine/cello/pkg/plugins/types"
	"github.com/volcengine/cello/pkg/plugins/utils"
	"github.com/volcengine/cello/pkg/utils/logger"
)

var dLg = log.Log.WithFields(logger.Fields{"component": "local device driver"})

type LocalNetDevice struct{}

func NewLocalNetDeviceDriver() *LocalNetDevice {
	return &LocalNetDevice{}
}

func (d *LocalNetDevice) Name() string {
	return "localNetDevice"
}

func (d *LocalNetDevice) SetupNetwork(config *types.SetupConfig) (err error) {
	targetLink, err := netlink.LinkByIndex(config.ENIIndex)
	if err != nil {
		err = fmt.Errorf("could not found parent device [index %d]", config.ENIIndex)
		return
	}
	err = netlink.LinkSetDown(targetLink)
	if err != nil {
		return fmt.Errorf("set link %s down failed, %v", targetLink.Attrs().Name, err)
	}
	tempName, err := ip.RandomVethName()
	if err != nil {
		return err
	}
	err = netlink.LinkSetName(targetLink, tempName)
	if err != nil {
		return fmt.Errorf("set link %s name to %s failed, %v", targetLink.Attrs().Name, tempName, err)
	}

	targetLink, err = netlink.LinkByName(tempName)
	if err != nil {
		err = fmt.Errorf("could not found parent device [index %d, name %s]", config.ENIIndex, tempName)
		return
	}
	config.Link = targetLink

	// setup device in pod ns
	var netns ns.NetNS
	netns, err = ns.GetNS(config.NetNSPath)
	if err != nil {
		err = fmt.Errorf("get ns handle for [%s] failed: %w", config.NetNSPath, err)
		return
	}

	defer func(netNs ns.NetNS) {
		inErr := netNs.Close()
		if inErr != nil {
			dLg.Errorf("Failed to close netns due to: %v", inErr)
		}
	}(netns)

	err = netlink.LinkSetNsFd(targetLink, int(netns.Fd()))
	if err != nil {
		err = fmt.Errorf("set link %s to netns failed: %w", targetLink.Attrs().Name, err)
		return
	}

	defer func() {
		if err != nil {
			_ = GenericTeardownNetwork(config.NetNSPath)
		}
	}()

	err = netns.Do(func(netNS ns.NetNS) error {
		podLink, err2 := netlink.LinkByName(tempName)
		if err2 != nil {
			return fmt.Errorf("could not find interface %s inside netns, %v", tempName, err2)
		}

		linkConfig := &device.Conf{
			IfName:    config.IfName,
			MTU:       targetLink.Attrs().MTU,
			Addresses: []*netlink.Addr{},
			Routes:    []*netlink.Route{},
			Rules:     []*netlink.Rule{},
			Neighs:    []*netlink.Neigh{},
			SysCtl:    [][]string{},
		}

		for _, ne := range config.ExtraNeigh {
			linkConfig.Neighs = append(linkConfig.Neighs, &netlink.Neigh{
				LinkIndex:    podLink.Attrs().Index,
				State:        netlink.NUD_PERMANENT,
				IP:           ne.Dst,
				HardwareAddr: ne.Mac,
			})
		}

		for i := range config.ExtraRoutes {
			linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
				Dst:       &config.ExtraRoutes[i].Dst,
				Gw:        config.ExtraRoutes[i].GW,
				LinkIndex: podLink.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Flags:     int(netlink.FLAG_ONLINK),
			})
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

			if config.DefaultRoute {
				// Default Route
				linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
					Table:     tableId,
					LinkIndex: podLink.Attrs().Index,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       defaultIPv4Route,
					Gw:        config.IPv4Gateway,
					//Flags:     int(netlink.FLAG_ONLINK),
				})
			}

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

			if config.DefaultRoute {
				// Default Route
				linkConfig.Routes = append(linkConfig.Routes, &netlink.Route{
					Table:     tableId,
					LinkIndex: podLink.Attrs().Index,
					Scope:     netlink.SCOPE_UNIVERSE,
					Gw:        config.IPv6Gateway,
					Dst:       defaultIPv6Route,
					//Flags:     int(netlink.FLAG_ONLINK),
				})
			}

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
