package cidr_test

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/100"
	"net"
	"path"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/volcengine/cello/pkg/plugins/ipam/cidr"
)

var _ = Describe("Cidr IPAM Allocator", func() {
	Context("allocator context", func() {
		cfg := cidr.Config{
			Mode:    "",
			DataDir: path.Join(tempDir, "allocator"),
			Ranges: map[string]allocator.RangeSet{
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
		allocators, err := cidr.NewAllocatorGroup(&cfg)
		Expect(err).NotTo(HaveOccurred())

		var sameIP *current.IPConfig
		It("should allocate an ip success from configured range", func() {
			sameIP, err = allocators.Get("abc", "containerdId1", "eth1", nil)
			Expect(err).NotTo(HaveOccurred())
			fmt.Fprintln(GinkgoWriter, "got ip", sameIP.String())

		})

		It("should allocate same ip while use same owner id again", func() {
			ipCfg, err := allocators.Get("abc", "containerdId1", "eth1", nil)
			Expect(err).NotTo(HaveOccurred())
			fmt.Fprintln(GinkgoWriter, "got ip", ipCfg.String())
			Expect(ipCfg).To(Equal(sameIP))
		})

		It("should allocate a different ip while use same owner id and different ifName", func() {
			ipCfg, err := allocators.Get("abc", "containerdId1", "eth2", nil)
			Expect(err).NotTo(HaveOccurred())
			fmt.Fprintln(GinkgoWriter, "got ip", ipCfg.String())
		})

		It("should fail while rangeSetId not exist", func() {
			_, err := allocators.Get("not exist", "containerdIdAny", "eth1", nil)
			Expect(err).To(MatchError("get allocator by not exist failed, not exist"))
		})

		It("should release ip success", func() {
			err := allocators.Release("abc", "containerdId1", "eth1")
			Expect(err).NotTo(HaveOccurred())
			err = allocators.Release("abc", "containerdId1", "eth2")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should release ip which not allocated success", func() {
			err := allocators.Release("def", "containerdId2", "eth1")
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
