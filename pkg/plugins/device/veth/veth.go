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

package veth

import (
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// Conf is interface config for veth pair.
type Conf struct {
	IfName   string
	PeerName string
	MTU      int
}

// Setup veth pair interface for netns.
func (c *Conf) Setup(netNS ns.NetNS) error {
	peer, err := netlink.LinkByName(c.PeerName)
	if err == nil {
		err = netlink.LinkDel(peer)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return err
			}
		}
	}

	tempIfName, err := ip.RandomVethName()
	if err != nil {
		return err
	}
	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			MTU:       c.MTU,
			Name:      tempIfName,
			Namespace: netlink.NsFd(int(netNS.Fd())),
		},
		PeerName: c.PeerName,
	}
	err = netlink.LinkAdd(link)
	if err != nil {
		return err
	}

	return netNS.Do(func(netNS ns.NetNS) error {
		inLink, inErr := netlink.LinkByName(tempIfName)
		if inErr != nil {
			return inErr
		}
		if inLink.Attrs().Name == c.IfName {
			return nil
		}
		return netlink.LinkSetName(inLink, c.IfName)
	})
}
