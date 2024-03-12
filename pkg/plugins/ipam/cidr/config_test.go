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

package cidr_test

import (
	"encoding/json"
	"net"
	"os"
	"path"
	"strings"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/volcengine/cello/pkg/plugins/ipam/cidr"
)

var _ = Describe("Cidr IPAM Config", func() {
	It("should load config from file success", func() {
		configData := cidr.Config{
			DataDir: path.Join(tempDir, "dir"),
			Ranges: map[string]*allocator.RangeSet{
				"abc": {allocator.Range{
					RangeStart: net.IP{198, 19, 50, 3},
					RangeEnd:   net.IP{198, 19, 50, 29},
					Subnet: cniTypes.IPNet{
						IP:   net.IP{198, 19, 50, 0},
						Mask: net.CIDRMask(27, 32),
					},
					Gateway: net.IP{198, 19, 50, 1},
				}},
				"def": {allocator.Range{
					RangeStart: net.IP{198, 19, 50, 35},
					RangeEnd:   net.IP{198, 19, 50, 62},
					Subnet: cniTypes.IPNet{
						IP:   net.IP{198, 19, 50, 32},
						Mask: net.CIDRMask(27, 32),
					},
					Gateway: net.IP{198, 19, 50, 33},
				}},
				"ghi": {allocator.Range{
					RangeStart: net.IP{198, 19, 58, 3},
					RangeEnd:   net.IP{198, 19, 58, 29},
					Subnet: cniTypes.IPNet{
						IP:   net.IP{198, 19, 58, 0},
						Mask: net.CIDRMask(27, 32),
					},
					Gateway: net.IP{198, 19, 58, 1},
				}},
			},
		}
		data, err := json.Marshal(configData)
		Expect(err).NotTo(HaveOccurred())
		configFile := path.Join(tempDir, "config")
		err = os.WriteFile(configFile, data, 0755)
		Expect(err).NotTo(HaveOccurred())
		config, err := cidr.LoadConfigFromFile(configFile)
		Expect(err).NotTo(HaveOccurred())

		Expect(config).To(Equal(&configData))
	})

	It("should return error if range start bigger than end", func() {
		ipAddr, subnet, _ := net.ParseCIDR("33.191.7.106/30")
		config := &cidr.Config{
			DataDir: path.Join(tempDir, "dir2"),
			Ranges: map[string]*allocator.RangeSet{
				"abc": {
					allocator.Range{
						RangeStart: ip.NextIP(ipAddr),
						Subnet:     cniTypes.IPNet(*subnet),
					},
				},
				"def": {
					allocator.Range{
						RangeStart: ipAddr,
						Subnet:     cniTypes.IPNet(*subnet),
					},
				},
			},
		}
		err := cidr.ValidateConfig(config)
		Expect(strings.Contains(err.Error(), "start not smaller than end")).To(Equal(true))
		Expect(strings.Contains(err.Error(), "abc")).To(Equal(true))
	})
})
