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

package meta

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
)

var (
	sysBusPCI = "/sys/bus/pci/devices"
)

func getLink(pciaddr string) (netlink.Link, error) {
	if len(pciaddr) > 0 {
		netDir := filepath.Join(sysBusPCI, pciaddr, "net")
		if _, err := os.Lstat(netDir); err != nil {
			virtioNetDir := filepath.Join(sysBusPCI, pciaddr, "virtio*", "net")
			matches, err := filepath.Glob(virtioNetDir)
			if len(matches) == 0 || err != nil {
				return nil, fmt.Errorf("no net directory under pci device %s", pciaddr)
			}
			netDir = matches[0]
		}
		fInfo, err := ioutil.ReadDir(netDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read net directory %s: %q", netDir, err)
		}
		if len(fInfo) > 0 {
			return netlink.LinkByName(fInfo[0].Name())
		}
		return nil, fmt.Errorf("failed to find device name for pci address %s", pciaddr)
	}

	return nil, fmt.Errorf("failed to find physical interface")
}

// Determine the last IP of a subnet, excluding the broadcast if IPv4
func lastIP(subnet net.IPNet) net.IP {
	var end net.IP
	for i := 0; i < len(subnet.IP); i++ {
		end = append(end, subnet.IP[i]|^subnet.Mask[i])
	}
	if subnet.IP.To4() != nil {
		end[3]--
	}

	return end
}
