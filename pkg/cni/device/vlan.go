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
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// VlanConfig is interface config of vlan slave.
type VlanConfig struct {
	MasterName   string
	IfName       string
	Vid          int
	MTU          int
	HardwareAddr net.HardwareAddr
}

// Setup vlan slave for netns.
func (vlanConfig *VlanConfig) Setup(netNS ns.NetNS) error {
	master, err := netlink.LinkByName(vlanConfig.MasterName)
	if err != nil {
		return fmt.Errorf("cannot found master link by name %s", vlanConfig.MasterName)
	}
	vlanName := generateVlanDeviceName(master.Attrs().Name, vlanConfig.Vid)
	vlan, err := netlink.LinkByName(vlanName)
	if err == nil {
		// del pre link
		err = netlink.LinkDel(vlan)
		if err != nil {
			return err
		}
	}
	if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return err
	}

	vlan = &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         vlanConfig.MTU,
			Name:        vlanName,
			ParentIndex: master.Attrs().Index,
			Namespace:   netlink.NsFd(int(netNS.Fd())),
		},
		VlanId: vlanConfig.Vid,
	}
	if vlanConfig.HardwareAddr.String() != "" {
		vlan.Attrs().HardwareAddr = vlanConfig.HardwareAddr
	}

	err = netlink.LinkAdd(vlan)
	if err != nil {
		return err
	}

	return netNS.Do(func(netNS ns.NetNS) error {
		contLink, innerErr := netlink.LinkByName(vlanName)
		if innerErr != nil {
			return innerErr
		}
		if contLink.Attrs().Name == vlanConfig.IfName {
			return nil
		}
		return netlink.LinkSetName(contLink, vlanConfig.IfName)

	})
}

func generateVlanDeviceName(masterName string, vlanID int) string {
	vlanName := fmt.Sprintf("%s.%d", masterName, vlanID)
	if len(vlanName) > 15 {
		vlanName = vlanName[len(vlanName)-15:]
	}
	return vlanName
}
