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

package device

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/cni/utils"
	"github.com/volcengine/cello/pkg/utils/iproute"
)

// Conf indicates network devices configures.
type Conf struct {
	IfName string
	MTU    int

	Addresses []*netlink.Addr
	Routes    []*netlink.Route
	Rules     []*netlink.Rule
	Neighs    []*netlink.Neigh
	SysCtl    [][]string
}

// Setup interfaces for container netns.
func Setup(link netlink.Link, conf *Conf) error {
	var err error
	if conf.IfName != "" && link.Attrs().Name != conf.IfName {
		err = netlink.LinkSetName(link, conf.IfName)
		if err != nil {
			return fmt.Errorf("link set name failed: %s", err.Error())
		}
		link, err = netlink.LinkByName(conf.IfName)
		if err != nil {
			return fmt.Errorf("could not find interface %d inside netns after name changed", link.Attrs().Index)
		}
	}

	if link.Attrs().OperState != netlink.OperUp {
		err = netlink.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to bring link %s up: %w", link.Attrs().Name, err)
		}
	}

	if conf.MTU > 0 && link.Attrs().MTU != conf.MTU {
		err = netlink.LinkSetMTU(link, conf.MTU)
		if err != nil {
			return fmt.Errorf("link %d set mtu failed: %s", link.Attrs().Index, err.Error())
		}
	}

	for _, v := range conf.SysCtl {
		if len(v) != 2 {
			return fmt.Errorf("sysctl config err")
		}
		err = utils.EnsureNetConfSet(link, v[0], v[1])
		if err != nil {
			return err
		}
	}

	for _, addr := range conf.Addresses {
		err = netlink.AddrReplace(link, addr)
		if err != nil {
			return fmt.Errorf("add address %s to link %s failed: %w", addr.String(), link.Attrs().Name, err)
		}
	}

	for _, neigh := range conf.Neighs {
		err = iproute.EnsureNeigh(neigh)
		if err != nil {
			return fmt.Errorf("ensure neigh failed: %w", err)
		}
	}

	for _, route := range conf.Routes {
		err = iproute.EnsureRoute(route)
		if err != nil {
			return fmt.Errorf("ensure route failed: %w", err)
		}
	}

	for _, rule := range conf.Rules {
		err = iproute.EnsureIPRule(rule)
		if err != nil {
			return fmt.Errorf("ensure rule failed: %w", err)
		}
	}

	return nil
}
