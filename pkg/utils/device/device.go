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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mellanox/rdmamap"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
)

const (
	netDevDir    = "/sys/class/net"
	sysBusPciDir = "/sys/bus/pci/devices"
)
var (
	ErrNoNetDir = errors.New("no net directory")
)

type NetDevice interface {
	IfName() string
	HwAddr() string
	PciId() string
	IsPciDevice() bool
}

type RdmaHCA struct {
	PciAddr string
	NetName string // maybe not unique
	Mac     string // maybe not unique
}

func (hca *RdmaHCA) IfName() string {
	return hca.NetName
}

func (hca *RdmaHCA) HwAddr() string {
	return hca.Mac
}

func (hca *RdmaHCA) PciId() string {
	return hca.PciAddr
}

func (hca *RdmaHCA) IsPciDevice() bool {
	return true
}

type NetDev RdmaHCA

func (n *NetDev) IfName() string {
	return n.NetName
}

func (n *NetDev) HwAddr() string {
	return n.Mac
}

func (n *NetDev) PciId() string {
	return n.PciAddr
}

func (n *NetDev) IsPciDevice() bool {
	return n.PciAddr != ""
}

// GetNetNamesByDeviceId returns host net interface names as string for a PCI device from its pci address
func GetNetNamesByDeviceId(pciAddr string) ([]string, error) {
	netDir := filepath.Join(sysBusPciDir, pciAddr, "net")
	if _, err := os.Lstat(netDir); err != nil {
		return nil, ErrNoNetDir
	}

	fInfos, err := os.ReadDir(netDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read net directory %s: %v", netDir, err)
	}

	names := make([]string, 0)
	for _, f := range fInfos {
		names = append(names, f.Name())
	}
	return names, nil
}

func IsRdma(pciAddr string) bool {
	return len(rdmamap.GetRdmaDevicesForPcidev(pciAddr)) > 0
}

func ListRdmaPciAddr() ([]string, error) {
	var list []string
	fInfos, err := os.ReadDir(sysBusPciDir)
	if err != nil {
		return nil, err
	}
	for _, f := range fInfos {
		if !IsRdma(f.Name()) {
			continue
		}
		list = append(list, f.Name())
	}
	return list, nil
}

func getNetMac(pciAddr, netName string) (string, error) {
	macFile := filepath.Join(sysBusPciDir, pciAddr, "net", netName, "address")
	mac, err := os.ReadFile(macFile)
	if err != nil {
		return "", fmt.Errorf("failde to read mac file %s: %v", macFile, err)
	}
	return string(mac), nil
}

// ListRdmaNetDevice list net devices of rdma devices which name has prefix.
func ListRdmaNetDevice(prefix string) ([]RdmaHCA, error) {
	var list []RdmaHCA
	pciAddress, err := ListRdmaPciAddr()
	if err != nil {
		return nil, err
	}
	for _, pci := range pciAddress {
		var expectedNames []string
		names, inErr := GetNetNamesByDeviceId(pci)
		if errors.Is(inErr, ErrNoNetDir) {
			continue
		} else if inErr != nil {
			return nil, inErr
		}

		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				expectedNames = append(expectedNames, n)
			}
		}
		if len(expectedNames) == 0 {
			return nil, fmt.Errorf("get net name which has 'eth' prefix for %s failed, empty", pci)
		}
		mac, inErr := getNetMac(pci, expectedNames[0])
		if inErr != nil {
			return nil, fmt.Errorf("get net mac for %s/net/%s failed, %v", pci, expectedNames[0], inErr)
		}
		list = append(list, RdmaHCA{
			PciAddr: pci,
			NetName: expectedNames[0],
			Mac:     mac,
		})
	}
	return list, nil
}

func GetDeviceByName(name string) (NetDevice, error) {
	dev := &NetDev{
		PciAddr: "",
		NetName: name,
		Mac:     "",
	}

	// Get device lladdr.
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("can't get device %v err: %v", name, err)
	}
	dev.Mac = link.Attrs().HardwareAddr.String()

	// Check if netdev is a pci device.
	busInfo, err := ethtool.BusInfo(name)
	if err == nil {
		dev.PciAddr = strings.Trim(busInfo, "\"")
	}
	return dev, nil
}

func GetAddrsFromDevice(deviceName string) ([]netlink.Addr, error) {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("link not found %v", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("address not found %v", err)
	}

	return addrs, nil
}

func ListLinksWithPrefix(prefix string) ([]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("can't list devices")
	}
	devicesList := make([]netlink.Link, 0, 10)
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, prefix) {
			devicesList = append(devicesList, link)
		}
	}
	return devicesList, nil

}
