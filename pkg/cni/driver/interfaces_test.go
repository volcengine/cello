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

package driver

import (
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/gdexlab/go-render/render"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/volcengine/cello/pkg/cni/types"
	daemonTypes "github.com/volcengine/cello/types"
)

func TestDataPathUseExclusiveENI(t *testing.T) {
	runtime.LockOSThread()
	var err error

	// Setup environment.
	hostNS, err := testutils.NewNS()
	assert.NoError(t, err)

	containerNS, err := testutils.NewNS()
	assert.NoError(t, err)

	err = hostNS.Set()
	assert.NoError(t, err)

	// Teardown environment.
	defer func() {
		err = containerNS.Close()
		assert.NoError(t, err)
		err = testutils.UnmountNS(containerNS)
		err = hostNS.Close()
		assert.NoError(t, err)
		err = testutils.UnmountNS(hostNS)
		assert.NoError(t, err)
	}()
	defer runtime.UnlockOSThread()

	// Data path test data.
	// Link.
	eniName := "eth1" //host if name
	eni, err := createDummyENI(eniName)
	assert.NoError(t, err)
	defer deleteDummyENI(eni.Attrs().Index)
	containerLinkName := "eth0"
	// IP && Route.
	containerIPv4, err := createIPNet("172.16.0.2/16")
	assert.NoError(t, err)
	ipv4Gateway := net.ParseIP("172.16.0.1")
	assert.NoError(t, err)
	containerIPv6, err := createIPNet("FEF6:BDFE:7654:593F:9721:20B0:C3C3:1A66/10")
	ipv6Gateway := net.ParseIP("FEF6:BDFE:7654:593F::1/10")
	assert.NoError(t, err)
	usePolicyRoute := false
	useLocalHostPath := false
	dataPathConfig := &types.SetupConfig{
		DP:                  types.ENI,
		ENIIndex:            eni.Attrs().Index,
		IfName:              containerLinkName,
		NetNSPath:           containerNS.Path(),
		BandWidth:           &types.BandwidthEntry{EgressRate: 10},
		IPv4:                containerIPv4,
		IPv4Gateway:         ipv4Gateway,
		IPv6:                containerIPv6,
		IPv6Gateway:         ipv6Gateway,
		DefaultRoute:        true,
		ExtraRoutes:         nil,
		PolicyRoute:         usePolicyRoute,
		RedirectToHostCIDRs: nil,
		LocalFastPath:       useLocalHostPath,
		VethNameInHost:      eniName,
		HostLink:            nil,
		HostIPSet:           nil,
		Vid:                 0,
		HardwareAddr:        nil,
	}

	// Test setup network.
	err = SetupDataPath(dataPathConfig)
	assert.NoError(t, err)
	// Check configs.
	link, err := netlink.LinkByIndex(eni.Attrs().Index)
	assert.Error(t, err)
	assert.Nil(t, link)
	_ = containerNS.Do(func(ns ns.NetNS) error {
		// Check for link.
		link, err := netlink.LinkByName(containerLinkName)
		assert.NoError(t, err)

		if assert.NotNil(t, link) {
			// Validate L2 config.
			// assert.Equal(t, netlink.LinkOperState(netlink.OperUp), link.Attrs().OperState)
			assert.Equal(t, eni.Attrs().MTU, link.Attrs().MTU)

			// Validate L3 config.
			// IPv4 config.
			ipv4s, err := netlink.AddrList(link, netlink.FAMILY_V4)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv4s) {
				assert.Equal(t, 1, len(ipv4s))
				assert.True(t, containerIPv4.IP.Equal(ipv4s[0].IP))
				assert.Equal(t, containerIPv4.Mask, ipv4s[0].Mask)
			}
			// IPv4 default route.
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv4Gateway, eni.Attrs().Index))
			}

			// IPv6 config.
			ipv6s, err := netlink.AddrList(link, netlink.FAMILY_V6)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv6s) && assert.Greater(t, len(ipv6s), 0) {
				for _, ip := range ipv6s {
					if !ip.IP.IsLinkLocalUnicast() && !ip.IP.IsLinkLocalMulticast() {
						assert.True(t, containerIPv6.IP.Equal(ip.IP))
						assert.Equal(t, containerIPv6.Mask, ip.Mask)
					}
				}
			} // IPv6 default route.
			routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
				Src: containerIPv6.IP,
				Dst: nil,
			}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv6Gateway, eni.Attrs().Index))
			}
			//TODO: Policy route.
			//TODO: Extra route.

		}
		return nil
	})

	// Test teardown network.
	err = TeardownNetwork(containerNS.Path())
	assert.NoError(t, err)

	_ = containerNS.Do(func(netNS ns.NetNS) error {

		links, err := netlink.LinkList()
		assert.NoError(t, err)
		for _, link := range links {
			// Check if address has been deleted.
			addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
			assert.NoError(t, err)
			assert.Zero(t, len(addrs))
		}

		return nil
	})

}

func TestDataPathUseSharedENI(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var err error

	// Setup environment.
	hostNS, err := testutils.NewNS()
	assert.NoError(t, err)

	containerNS1, err := testutils.NewNS()
	assert.NoError(t, err)

	containerNS2, err := testutils.NewNS()
	assert.NoError(t, err)

	err = hostNS.Set()
	assert.NoError(t, err)

	// Teardown environment.
	defer func() {
		err := hostNS.Close()
		assert.NoError(t, err)

		err = containerNS1.Close()
		assert.NoError(t, err)

		err = containerNS2.Close()
		assert.NoError(t, err)

		err = testutils.UnmountNS(hostNS)
		assert.NoError(t, err)
		err = testutils.UnmountNS(containerNS1)
		assert.NoError(t, err)
		err = testutils.UnmountNS(containerNS2)
		assert.NoError(t, err)
	}()

	// Data path test data.
	// Link.
	eniName := "eth1" //host if name
	eni, err := createDummyENI(eniName)
	assert.NoError(t, err)
	defer deleteDummyENI(eni.Attrs().Index)
	containerLinkName := "eth0"
	hostLink, err := createDummyENI("eth0")
	assert.NoError(t, err)
	defer deleteDummyENI(hostLink.Attrs().Index)

	// IP && Route.
	hostIPV4, _, err := net.ParseCIDR("172.16.0.2/16")
	assert.NoError(t, err)
	err = netlink.AddrReplace(hostLink, &netlink.Addr{
		IPNet: netlink.NewIPNet(hostIPV4),
	})
	assert.NoError(t, err)
	hostIPV6, _, err := net.ParseCIDR("2408:1000:abff:ff00:c7a3:b4c1:f9f5:e4b/56")
	assert.NoError(t, err)
	err = netlink.AddrReplace(hostLink, &netlink.Addr{
		IPNet: netlink.NewIPNet(hostIPV6),
	})

	assert.NoError(t, err)
	ip, container1IPv4, err := net.ParseCIDR("172.16.0.3/16")
	assert.NoError(t, err)
	container1IPv4.IP = ip
	ip, container2IPv4, err := net.ParseCIDR("172.16.0.4/16")
	assert.NoError(t, err)
	container2IPv4.IP = ip
	ipv4Gateway := net.ParseIP("172.16.0.1")
	assert.NoError(t, err)
	ip, container1IPv6, err := net.ParseCIDR("2408:1000:abff:ff00:a6d1:b7a2:d9e3:c2f/56")
	assert.NoError(t, err)
	container1IPv6.IP = ip
	ip, container2IPv6, err := net.ParseCIDR("2408:1000:abff:ff00:e5c7:a1b4:f3d9:e6a/56")
	assert.NoError(t, err)
	container2IPv6.IP = ip
	ipv6Gateway := net.ParseIP("2408:1000:abff:ff00::1")
	assert.NoError(t, err)
	usePolicyRoute := false
	useLocalFastPath := true
	_, redirV4CIDR, _ := net.ParseCIDR("169.254.0.0/16")
	_, redirV6CIDR, _ := net.ParseCIDR("2408:1000:abff:ff::/56")
	dataPathConfig := &types.SetupConfig{
		DP:           types.IPVlan,
		ENIIndex:     eni.Attrs().Index,
		IfName:       containerLinkName,
		NetNSPath:    containerNS1.Path(),
		IPv4:         container1IPv4,
		IPv4Gateway:  ipv4Gateway,
		IPv6:         container1IPv6,
		IPv6Gateway:  ipv6Gateway,
		BandWidth:    &types.BandwidthEntry{EgressRate: 10},
		DefaultRoute: true,
		ExtraRoutes:  nil,
		PolicyRoute:  usePolicyRoute,
		RedirectToHostCIDRs: []*net.IPNet{
			redirV4CIDR,
			redirV6CIDR,
		},
		LocalFastPath:  useLocalFastPath,
		VethNameInHost: eniName,
		HostLink:       hostLink,
		HostIPSet: &daemonTypes.IPSet{
			IPv4: hostIPV4,
			IPv6: hostIPV6,
		},
		Vid:          0,
		HardwareAddr: nil,
	}
	t.Log(render.Render(dataPathConfig))

	// Add legacy filter.
	err = ensureClsActQdsic(eni)
	assert.NoError(t, err)
	err = addLegacyU32Filter(eni.Attrs().Index)
	assert.NoError(t, err)

	// Setup container1.
	err = SetupDataPath(dataPathConfig)
	assert.NoError(t, err)
	// Setup container2.
	dataPathConfig.NetNSPath = containerNS2.Path()
	dataPathConfig.IPv4 = container2IPv4
	dataPathConfig.IPv6 = container2IPv6
	err = SetupDataPath(dataPathConfig)
	assert.NoError(t, err)

	// Check container1 configs.
	_ = containerNS1.Do(func(ns ns.NetNS) error {
		// Check for link.
		link, err := netlink.LinkByName(containerLinkName)
		assert.NoError(t, err)

		if assert.NotNil(t, link) {
			// Validate L2 config.
			//assert.Equal(t, netlink.OperUp, link.Attrs().OperState)
			assert.Equal(t, eni.Attrs().MTU, link.Attrs().MTU)

			// Validate L3 config.
			// IPv4 config.
			ipv4s, err := netlink.AddrList(link, netlink.FAMILY_V4)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv4s) {
				assert.Equal(t, 1, len(ipv4s))
				assert.True(t, container1IPv4.IP.Equal(ipv4s[0].IP))
				assert.Equal(t, container1IPv4.Mask, ipv4s[0].Mask)
			}

			// IPv4 default route.
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
				Dst: nil,
			}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv4Gateway, link.Attrs().Index))
			}
			// IPv6 config.
			ipv6s, err := netlink.AddrList(link, netlink.FAMILY_V6)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv6s) && assert.Greater(t, len(ipv6s), 0) {
				for _, ipv6s := range ipv6s {
					if !ipv6s.IP.IsLinkLocalUnicast() && !ipv6s.IP.IsLinkLocalMulticast() {
						// Should only have one IPv6 address.
						assert.Equal(t, container1IPv6.IP, ipv6s.IP)
					}
				}
			}
			// IPv6 default route.
			routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
				Src: container1IPv6.IP,
				Dst: nil,
			}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv6Gateway, link.Attrs().Index))
			}
		}
		//TODO: Policy route.
		//TODO: Extra route.

		return nil
	})

	// Check container2 configs.
	_ = containerNS2.Do(func(ns ns.NetNS) error {
		// Check for link.
		link, err := netlink.LinkByName(containerLinkName)
		assert.NoError(t, err)

		if assert.NotNil(t, link) {
			// Validate L2 config.
			//assert.Equal(t, netlink.OperUp, link.Attrs().OperState)
			assert.Equal(t, eni.Attrs().MTU, link.Attrs().MTU)
			// Validate L3 config.
			// IPv4 config.
			ipv4s, err := netlink.AddrList(link, netlink.FAMILY_V4)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv4s) {
				assert.Equal(t, 1, len(ipv4s))
				assert.True(t, container2IPv4.IP.Equal(ipv4s[0].IP))
			}
			// IPv4 default route.
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
				Dst: nil,
			}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv4Gateway, link.Attrs().Index))
			}

			// IPv6 config.
			ipv6s, err := netlink.AddrList(link, netlink.FAMILY_V6)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv6s) && assert.Greater(t, len(ipv6s), 0) {
				for _, ip := range ipv6s {
					if !ip.IP.IsLinkLocalUnicast() && !ip.IP.IsLinkLocalMulticast() {
						// Should only have one IPv6 address.
						assert.Equal(t, container2IPv6.IP, ip.IP)
					}
				}
			}

			// IPv6 default route.
			routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
				Src: container2IPv6.IP,
				Dst: nil,
			}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv6Gateway, link.Attrs().Index))
			}
		}
		//TODO: Policy route.
		//TODO: Extra route.

		return nil
	})

	// Check local fast path.
	links, err := netlink.LinkList()
	assert.NoError(t, err)
	hasFastPath := false
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, "ipvl_") {
			hasFastPath = true
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
				LinkIndex: link.Attrs().Index,
			}, netlink.RT_FILTER_OIF)
			assert.NoError(t, err)
			assert.NotNil(t, routes)
			assert.NotZero(t, len(routes))
			assert.True(t, hasDstRoute(routes, container1IPv4.IP, link.Attrs().Index))
			assert.True(t, hasDstRoute(routes, container1IPv6.IP, link.Attrs().Index))
			assert.True(t, hasDstRoute(routes, container2IPv4.IP, link.Attrs().Index))
			assert.True(t, hasDstRoute(routes, container2IPv6.IP, link.Attrs().Index))
		}

	}
	assert.True(t, hasFastPath)

	// Check for filters.
	filters, err := netlink.FilterList(eni, qdiscHandle)
	assert.NoError(t, err)
	assert.NotEqual(t, 0, len(filters))
	hasV4SrcEgressFilter := false
	hasV6SrcEgressFilter := false
	hasV4DstFilter := false
	hasV6DstFilter := false
	for _, filter := range filters {
		flower, ok := filter.(*netlink.Flower)
		assert.True(t, ok)
		if flower.SrcIP != nil && flower.SrcIP.Equal(hostIPV4) {
			hasV4SrcEgressFilter = true
			act := flower.Actions[0].(*netlink.MirredAction)
			assert.Equal(t, hostLink.Attrs().Index, act.Ifindex)
			continue
		}
		if flower.SrcIP != nil && flower.SrcIP.Equal(hostIPV6) {
			hasV6SrcEgressFilter = true
			act := flower.Actions[0].(*netlink.MirredAction)
			assert.Equal(t, hostLink.Attrs().Index, act.Ifindex)
			continue
		}
		if flower.DestIP.Equal(redirV4CIDR.IP) &&
			flower.DestIPMask.String() == redirV4CIDR.Mask.String() {
			hasV4DstFilter = true
			assert.Equal(t, 3, len(flower.Actions))
			hasMirredAct, hasTunKeyAct, hasSkbEditAct := false, false, false
			for _, act := range flower.Actions {
				switch act.Type() {
				case "tunnel_key":
					hasTunKeyAct = true
					break
				case "mirred":
					hasMirredAct = true
				case "skbedit":
					hasSkbEditAct = true
				}
			}
			assert.True(t, hasSkbEditAct && hasTunKeyAct && hasMirredAct)
		}
		if flower.DestIP.Equal(redirV6CIDR.IP) &&
			flower.DestIPMask.String() == redirV6CIDR.Mask.String() {
			hasV6DstFilter = true
			assert.Equal(t, 3, len(flower.Actions))
			hasMirredAct, hasTunKeyAct, hasSkbEditAct := false, false, false
			for _, act := range flower.Actions {
				switch act.Type() {
				case "tunnel_key":
					hasTunKeyAct = true
					break
				case "mirred":
					hasMirredAct = true
				case "skbedit":
					hasSkbEditAct = true
				}
			}
			assert.True(t, hasSkbEditAct && hasTunKeyAct && hasMirredAct)
		}
	}
	assert.True(t, hasV4SrcEgressFilter)
	assert.True(t, hasV6SrcEgressFilter)
	assert.True(t, hasV4DstFilter)
	assert.True(t, hasV6DstFilter)

	// Test teardown ns1 network.
	err = TeardownNetwork(containerNS1.Path())
	assert.NoError(t, err)
	_ = containerNS1.Do(func(netNS ns.NetNS) error {
		link, err := netlink.LinkByName(containerLinkName)
		assert.Error(t, err)
		assert.Nil(t, link)
		return nil
	})

	// Check fast path removed.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Dst: container1IPv4,
	}, netlink.RT_FILTER_DST)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(routes))
	routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
		Dst: container1IPv6,
	}, netlink.RT_FILTER_DST)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(routes))

	// Test teardown ns2 network.
	err = TeardownNetwork(containerNS1.Path())
	assert.NoError(t, err)
	_ = containerNS1.Do(func(netNS ns.NetNS) error {
		link, err := netlink.LinkByName(containerLinkName)
		assert.Error(t, err)
		assert.Nil(t, link)
		return nil
	})

	// Check fast path removed.
	routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Dst: container2IPv4,
	}, netlink.RT_FILTER_DST)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(routes))
	routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
		Dst: container2IPv6,
	}, netlink.RT_FILTER_DST)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(routes))

}

func TestDataPathUseTrunkENI(t *testing.T) {
	runtime.LockOSThread()
	var err error

	// Setup environment.
	hostNS, err := testutils.NewNS()
	assert.NoError(t, err)

	containerNS, err := testutils.NewNS()
	assert.NoError(t, err)

	err = hostNS.Set()
	assert.NoError(t, err)

	// Teardown environment.
	defer func() {
		err = containerNS.Close()
		assert.NoError(t, err)
		err = testutils.UnmountNS(containerNS)
		assert.NoError(t, err)
		err = hostNS.Close()
		assert.NoError(t, err)
		err = testutils.UnmountNS(hostNS)
	}()
	defer runtime.UnlockOSThread()

	// Data path test data.
	// Link.
	eniName := "eth1" //host if name
	eni, err := createDummyENI(eniName)
	defer deleteDummyENI(eni.Attrs().Index)
	containerLinkName := "eth0"
	hostLink, err := createDummyENI("eth0")
	defer deleteDummyENI(hostLink.Attrs().Index)
	vlanID := 100
	macAddress, err := net.ParseMAC("30:AD:2A:50:EE:52")
	assert.NoError(t, err)
	// IP && Route.
	hostIPV4, _, err := net.ParseCIDR("172.16.0.2/16")
	err = netlink.AddrReplace(hostLink, &netlink.Addr{
		IPNet: netlink.NewIPNet(hostIPV4),
	})
	hostIPV6, _, err := net.ParseCIDR("2408:1000:abff:ff00:c7a3:b4c1:f9f5:e4b/56")
	err = netlink.AddrReplace(hostLink, &netlink.Addr{
		IPNet: netlink.NewIPNet(hostIPV6),
	})
	containerIPv4, err := createIPNet("172.16.0.2/16")
	assert.NoError(t, err)
	ipv4Gateway := net.ParseIP("172.16.0.1")
	assert.NoError(t, err)
	containerIPv6, err := createIPNet("2408:1000:abff:ff00:a6d1:b7a2:d9e3:c2f/56")
	ipv6Gateway := net.ParseIP("2408:1000:abff:ff00::1")
	assert.NoError(t, err)
	usePolicyRoute := false
	useLocalHostPath := true
	dataPathConfig := &types.SetupConfig{
		DP:                  types.Vlan,
		ENIIndex:            eni.Attrs().Index,
		IfName:              containerLinkName,
		NetNSPath:           containerNS.Path(),
		BandWidth:           &types.BandwidthEntry{EgressRate: 10},
		IPv4:                containerIPv4,
		IPv4Gateway:         ipv4Gateway,
		IPv6:                containerIPv6,
		IPv6Gateway:         ipv6Gateway,
		DefaultRoute:        true,
		ExtraRoutes:         nil,
		PolicyRoute:         usePolicyRoute,
		RedirectToHostCIDRs: nil,
		LocalFastPath:       useLocalHostPath,
		VethNameInHost:      "cel_001",
		HostLink:            hostLink,
		HostIPSet: &daemonTypes.IPSet{
			IPv4: hostIPV4,
			IPv6: hostIPV6,
		},
		Vid:          uint32(vlanID),
		HardwareAddr: macAddress,
	}

	err = SetupDataPath(dataPathConfig)
	assert.NoError(t, err)
	// Check configs.
	link, err := netlink.LinkByIndex(eni.Attrs().Index)
	assert.NoError(t, err)
	assert.NotNil(t, link)
	_ = containerNS.Do(func(ns ns.NetNS) error {
		// Check for link.
		link, err := netlink.LinkByName(containerLinkName)
		assert.NoError(t, err)

		if assert.NotNil(t, link) {
			// Validate L2 config.
			// assert.Equal(t, netlink.LinkOperState(netlink.OperUp), link.Attrs().OperState)
			assert.Equal(t, eni.Attrs().MTU, link.Attrs().MTU)
			assert.Equal(t, macAddress.String(), link.Attrs().HardwareAddr.String())

			// Validate L3 config.
			// IPv4 config.
			ipv4s, err := netlink.AddrList(link, netlink.FAMILY_V4)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv4s) {
				assert.Equal(t, 1, len(ipv4s))
				assert.True(t, containerIPv4.IP.Equal(ipv4s[0].IP))
				assert.Equal(t, containerIPv4.Mask, ipv4s[0].Mask)
			}
			// IPv4 default route.
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv4Gateway, eni.Attrs().Index))
			}

			// IPv6 config.
			ipv6s, err := netlink.AddrList(link, netlink.FAMILY_V6)
			assert.NoError(t, err)
			if assert.NotNil(t, ipv6s) && assert.Greater(t, len(ipv6s), 0) {
				for _, ip := range ipv6s {
					if !ip.IP.IsLinkLocalUnicast() && !ip.IP.IsLinkLocalMulticast() {
						assert.True(t, containerIPv6.IP.Equal(ip.IP))
						assert.Equal(t, containerIPv6.Mask, ip.Mask)
					}
				}
			} // IPv6 default route.
			routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
				Src: containerIPv6.IP,
				Dst: nil,
			}, netlink.RT_FILTER_DST)
			assert.NoError(t, err)
			if assert.NotNil(t, routes) {
				assert.True(t, hasDefaultRoute(routes, ipv6Gateway, eni.Attrs().Index))
			}
			//TODO: Policy route.
			//TODO: Extra route.

		}
		return nil
	})

	// Check local fast path.
	links, err := netlink.LinkList()
	assert.NoError(t, err)
	hasFastPath := false
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, "cel") {
			hasFastPath = true
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
				LinkIndex: link.Attrs().Index,
			}, netlink.RT_FILTER_OIF)
			assert.NoError(t, err)
			assert.NotNil(t, routes)
			assert.NotZero(t, len(routes))
			assert.True(t, hasDstRoute(routes, containerIPv4.IP, link.Attrs().Index))
			assert.True(t, hasDstRoute(routes, containerIPv6.IP, link.Attrs().Index))
		}
	}
	assert.True(t, hasFastPath)

	//TODO: Check filters.

	// Test teardown network.
	err = TeardownNetwork(containerNS.Path())
	assert.NoError(t, err)
	_ = containerNS.Do(func(netNS ns.NetNS) error {
		link, err := netlink.LinkByName(containerLinkName)
		assert.Error(t, err)
		assert.Nil(t, link)
		return nil
	})

	// Check fast path removed.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Dst: containerIPv4,
	}, netlink.RT_FILTER_DST)
	assert.Equal(t, 0, len(routes))
	routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
		Dst: containerIPv6,
	}, netlink.RT_FILTER_DST)
	assert.Equal(t, 0, len(routes))

}

func createDummyENI(name string) (netlink.Link, error) {
	err := netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:      name,
			OperState: netlink.OperUp,
		},
	})
	if err != nil {
		return nil, err
	}
	eni, err := netlink.LinkByName(name)
	return eni, err
}

func deleteDummyENI(ifIndex int) {
	link, err := netlink.LinkByIndex(ifIndex)
	if err != nil && link != nil {
		_ = netlink.LinkDel(link)
	}
}

func addLegacyU32Filter(linkIndex int) error {
	return netlink.FilterAdd(&netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    uint32(netlink.HANDLE_CLSACT&0xffff0000 | netlink.HANDLE_MIN_EGRESS&0x0000ffff),
			Priority:  defaultFlowerFilterPriority,
			Protocol:  unix.ETH_P_IP,
		},
		Sel: &netlink.TcU32Sel{
			Nkeys: 1,
			Flags: nl.TC_U32_TERMINAL,
			Keys: []netlink.TcU32Key{
				{
					Mask: 0xffffffff,
					Val:  0xAC100001,
					Off:  16,
				},
			},
		},
		Actions: nil,
	})
}

func hasDefaultRoute(routes []netlink.Route, gateway net.IP, dstIfIndex int) bool {
	for _, route := range routes {
		if route.LinkIndex == dstIfIndex && route.Gw.Equal(gateway) {
			return true
		}
	}
	return false
}

func hasDstRoute(routes []netlink.Route, dstIP net.IP, dstIfIndex int) bool {
	for _, route := range routes {
		if route.LinkIndex == dstIfIndex && route.Dst.IP.Equal(dstIP) {
			return true
		}
	}
	return false
}

func createIPNet(cidr string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ipNet.IP = ip
	return ipNet, nil
}
