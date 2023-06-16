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

package netns

import (
	"fmt"
	"os"

	"github.com/vishvananda/netns"
)

const nsRootPath = "/var/run/netns"

// CheckNetNsExist check if netns exists,
// if there is an error, return false and error.
func CheckNetNsExist(nsPath string) (bool, error) {
	h, err := netns.GetFromPath(nsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer func(h *netns.NsHandle) {
		_ = h.Close()
	}(&h)
	return true, nil
}

func ListAllNetNs() ([]string, error) {
	var namespaces []string
	files, err := os.ReadDir(nsRootPath)
	if err != nil {
		return namespaces, fmt.Errorf("read dir %s failed: %v", nsRootPath, err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		namespaces = append(namespaces, fmt.Sprintf("%s/%s", nsRootPath, f.Name()))
	}
	return namespaces, nil
}
