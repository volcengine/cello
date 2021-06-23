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
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/cni/log"
)

// IPVlanConf is interface config for IPVlan slaves.
type IPVlanConf struct {
	MasterName string
	IfName     string
	MTU        int
}

func randomIPVlanIfName() (string, error) {
	entropy := make([]byte, 6)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("get random string failed: %s", err.Error())
	}

	h := sha1.New()
	_, err = h.Write(entropy)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s", "ipvl", hex.EncodeToString(h.Sum(nil))[:11]), nil
}

// Setup IPVlan slave interface for netns.
func (c *IPVlanConf) Setup(netNS ns.NetNS) error {
	masterLink, err := netlink.LinkByName(c.MasterName)
	if err != nil {
		log.Log.Errorf("LinkByName error, err:%s", err.Error())
		return err
	}

	tempIfName, err := randomIPVlanIfName()
	if err != nil {
		return err
	}

	link := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         c.MTU,
			Name:        tempIfName,
			Namespace:   netlink.NsFd(int(netNS.Fd())),
			ParentIndex: masterLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}

	err = netlink.LinkAdd(link)
	if err != nil {
		log.Log.Errorf("LinkAdd error, err:%s", err.Error())
		return err
	}

	err = netNS.Do(func(netNS ns.NetNS) error {
		link, inErr := netlink.LinkByName(tempIfName)
		if inErr != nil {
			return inErr
		}
		if link.Attrs().Name == c.IfName {
			return nil
		}
		return netlink.LinkSetName(link, c.IfName)
	})
	if err != nil {
		log.Log.Errorf("LinkSetName error, err:%s", err.Error())
	}
	return err
}
