package cidr_test

import (
	"encoding/json"
	"net"
	"os"
	"path"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
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
		err = cidr.PrepareConfig(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(config).To(Equal(&configData))
	})
})
