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

package utils

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/vishvananda/netlink"
)

// routePreferenceStart is the start table ID for policy route table.
const routePreferenceStart = 1000

// EnsureNetConfSet calls sysctl to ensure system network config.
func EnsureNetConfSet(link netlink.Link, item, conf string) error {
	_, err := sysctl.Sysctl(fmt.Sprintf(item, link.Attrs().Name), conf)
	if err != nil {
		return fmt.Errorf("ensure net config %s to %s failed: %s", item, conf, err.Error())
	}
	return nil
}

// GetPolicyRouteTableID returns routePreferenceStart(1000) + linkIndex as route table index.
func GetPolicyRouteTableID(linkIndex int) int {
	return routePreferenceStart + linkIndex
}

// VethNameForPod returns host-side veth name for pod.
func VethNameForPod(name, namespace, ifName, prefix string) (string, error) {
	h := sha1.New()
	if ifName == "eth0" {
		ifName = ""
	}
	_, err := h.Write([]byte(namespace + "." + name + ifName))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(h.Sum(nil))[:11]), nil
}
