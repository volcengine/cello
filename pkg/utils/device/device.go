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
	"path/filepath"
)

var (
	sysBusPci = "/sys/bus/pci/devices"
)

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

func GetNetMac(pciAddr, netName string) (string, error) {
	macFile := filepath.Join(sysBusPci, pciAddr, "net", netName, "address")
	mac, err := os.ReadFile(macFile)
	if err != nil {
		return "", fmt.Errorf("failde to read mac file %s: %v", macFile, err)
	}
	return string(mac), nil
}
