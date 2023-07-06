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
	"os"
	"strings"

	"github.com/Mellanox/rdmamap"
	"path/filepath"
)

var (
	sysBusPci = "/sys/bus/pci/devices"
)

type Rdma struct {
	PciAddr string
	NetName string // maybe not unique
	Mac     string // maybe not unique
}

// GetNetNamesByDeviceId returns host net interface names as string for a PCI device from its pci address
func GetNetNamesByDeviceId(pciAddr string) ([]string, error) {
	netDir := filepath.Join(sysBusPci, pciAddr, "net")
	if _, err := os.Lstat(netDir); err != nil {
		return nil, fmt.Errorf("no net directory under pci device %s: %v", pciAddr, err)
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
	fInfos, err := os.ReadDir(sysBusPci)
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
	macFile := filepath.Join(sysBusPci, pciAddr, "net", netName, "address")
	mac, err := os.ReadFile(macFile)
	if err != nil {
		return "", fmt.Errorf("failde to read mac file %s: %v", macFile, err)
	}
	return string(mac), nil
}

func ListRdma() ([]Rdma, error) {
	var list []Rdma
	pciAddress, err := ListRdmaPciAddr()
	if err != nil {
		return nil, err
	}
	for _, pci := range pciAddress {
		var expectedNames []string
		names, inErr := GetNetNamesByDeviceId(pci)
		if inErr != nil {
			return nil, inErr
		}
		for _, n := range names {
			if strings.HasPrefix(n, "eth") {
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
		list = append(list, Rdma{
			PciAddr: pci,
			NetName: expectedNames[0],
			Mac:     mac,
		})
	}
	return list, nil
}
