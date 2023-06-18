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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cni100 "github.com/containernetworking/cni/pkg/types/100"
	cniIp "github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	netutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	utilsnet "k8s.io/utils/net"

	client2 "github.com/volcengine/cello/pkg/cni/client"
	"github.com/volcengine/cello/pkg/cni/log"
	types2 "github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/pbrpc"
)

const (
	defaultCniTimeout       = 120 * time.Second
	podNetworkDefinitionKey = "k8s.volcengine.com/pod-networks-definition"
	PodNetworksKey          = "k8s.volcengine.com/pod-networks"
	cniConfLocal            = "local"
	defaultConfDir          = "/etc/cni/net.d"
	defaultBinDir           = "/opt/cni/bin"
	defaultCNIDir           = "/var/lib/cni/cello"
	defaultCNIMetaDir       = "/var/lib/cni/cello-meta"
	defaultCNIMetaDeviceDir = "/var/lib/cni/cello-meta/devices"
	networkStatusKey        = "k8s.volcengine.com/network-status"
	defaultTableBase        = 100
	fakeIPRangesForDelete   = "127.0.0.0/30" // host-local want ipRanges when CNI DEL
)

var (
	// cniConfDir config for test
	cniConfDir = defaultConfDir
)

var (
	celloClient pbrpc.CelloClient
	conn        *grpc.ClientConn
	patchStatus bool
)

type IPRangeSourceType string

const (
	IPRangeSourceNone            = ""
	IPRangeSourceNetDeviceSelf   = "netDeviceSelf"
	IpRangeSourceNetDeviceSubnet = "netDeviceSubnet"
)

const (
	RuntimeConfigOptionTrunkMac = "trunkMac"
	RuntimeConfigOptionVlanID   = "vlanID"
)

type DelegateNetConf struct {
	Conf           MetaDelegateNetConf
	ConfList       MetaDelegateNetConfList
	Name           string
	ConfListPlugin bool // mark NetConfList
	PodNetwork     *PodNetwork
	MetaRequest    MetaRequest
	Index          int // master plugin index == 0

	// MetaConfig is build by MetaRequest
	MetaConfig MetaConfig `json:"metaConfig,omitempty"`

	Bytes []byte
}

type MetaNetConf struct {
	cniTypes.NetConf

	// defaultCniType means default cni for meta call
	DefaultCniType string `json:"defaultCni,omitempty"`

	// call cni with annotation
	RuntimeConfig RuntimeConfig `json:"runtimeConfig,omitempty"`

	// use LogLevel to set cni log
	LogLevel string `json:"logLevel,omitempty"`
}

// RuntimeConfig specifies CNI RuntimeConfig
type RuntimeConfig struct {
	PortMaps       []*PortMapEntry        `json:"portMappings,omitempty"`
	Bandwidth      *types2.BandwidthEntry `json:"bandwidth,omitempty"`
	PodAnnotations map[string]string      `json:"io.kubernetes.cri.pod-annotations,omitempty"`
	IPRanges       []RangeSet             `json:"ipRanges,omitempty"`
	DeviceID       string                 `json:"deviceID,omitempty"`
	IPs            []*cniIp.IP            `json:"ips,omitempty"`
	Mac            string                 `json:"mac,omitempty"`

	// custom
	// NetworkInterfaceConfig get network interface config from here, skip cello agent CreateEndpoint grpc
	NetworkInterfaceConfig *types2.NetworkInterfaceConfig `json:"com.volcengine.k8s.network-interface,omitempty"`
}

type RangeSet []Range

type Range struct {
	RangeStart net.IP         `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   net.IP         `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     cniTypes.IPNet `json:"subnet"`
	Gateway    net.IP         `json:"gateway,omitempty"`
}

// PortMapEntry for CNI PortMapEntry
type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	HostIP        string `json:"hostIP,omitempty"`
}

// TODO: Deprecated: use catena config -------------
type PodNetwork struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`

	CniConf    *CniConf    `json:"cniConf,omitempty"`
	DeviceConf *DeviceConf `json:"deviceConf,omitempty"`

	// Traffic is the traffic for user define
	Traffic *Traffic `json:"traffic,omitempty"`

	// Master mark net is master interface
	Master bool `json:"master,omitempty"`

	// Deprecated: use new config
	Ipv4 string `json:"ipv4,omitempty"`
	// Deprecated: use new config
	Mac string `json:"mac,omitempty"`
	// Deprecated: use new config
	Route *Route `json:"route,omitempty"`
	// Deprecated: use new config
	VlanID string `json:"vlanID,omitempty"`
}

type CniConf struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
}

type DeviceConf struct {
	Options map[string]string `json:"options,omitempty"`
	IPs     []string          `json:"ips,omitempty"`
	IfName  string            `json:"ifName,omitempty"`
	Mac     string            `json:"mac,omitempty"`
}

type Traffic struct {
	Routes Routes `json:"routes,omitempty"`
}

type NetNsConfig struct {
	DeviceName   string             `json:"deviceName,omitempty"`
	Ips          []*cni100.IPConfig `json:"ips,omitempty"`
	TableId      int                `json:"tableId,omitempty"`
	DefaultRoute bool               `json:"defaultRoute,omitempty"`
	ExtraRoutes  []Route            `json:"extraRoutes,omitempty"`
}

type Routes struct {
	ExtraRoutes []Route `json:"extraRoutes"`
	IsDefault   bool    `json:"default"`
}

// Route means one route rule
type Route struct {
	// Dst means the destination address
	Dst string `json:"dst,omitempty"`
	Gw  string `json:"gw,omitempty"`
}

type RealRoute struct {
	Dst     *net.IPNet
	Gw      net.IP
	Dev     netlink.Link
	TableId int
}

type PodNetworkDefinition struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type MetaDelegateNetConf struct {
	cniTypes.NetConf
	MetaRequest MetaRequest `json:"meta,omitempty"`
}

type MetaDelegateNetConfList struct {
	cniTypes.NetConfList
	MetaRequest MetaRequest `json:"meta,omitempty"`
}

type MetaRequest struct {
	IPRangesSource string `json:"ipRangesSource,omitempty"`
	ResourceName   string `json:"resourceName,omitempty"`
}

type MetaConfig struct {
	// IPRanges is only used internal housekeeping
	IPRanges []RangeSet `json:"ipRanges,omitempty"`
	// DeviceID is only used internal housekeeping
	DeviceID string `json:"deviceID,omitempty"`
}

type DeviceInfo struct {
	IfName string   `json:"ifName,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	Mac    string   `json:"mac,omitempty"`
}

type NetworkStatus struct {
	CNIName    string     `json:"cniName,omitempty"`
	DeviceInfo DeviceInfo `json:"deviceInfo,omitempty"`
}

// TODO: Deprecated: use catena config -----------

func CmdAdd(args *skel.CmdArgs) error {
	return cmdAdd(args)
}

func getDefaultNetConf() *MetaNetConf {
	return &MetaNetConf{
		DefaultCniType: types2.CelloChainer,
	}
}

func getDefaultPodNetworks(cniConfig *MetaNetConf) []*PodNetwork {
	return []*PodNetwork{
		{
			Namespace: "kube-system",
			Name:      "default",
			CniConf: &CniConf{
				Name: cniConfig.DefaultCniType,
				From: cniConfLocal,
			},
		},
	}
}

func loadCelloClient(ctx context.Context) error {
	var err error
	if celloClient != nil {
		return nil
	}
	celloClient, conn, err = client2.NewCelloClient(ctx)
	if err != nil {
		return err
	}
	return nil
}

func parseCmdArgs(args *skel.CmdArgs) (*MetaNetConf, *types2.K8SArgs, error) {

	var err error
	// parse config in cni conf file
	conf := getDefaultNetConf()
	if err = json.Unmarshal(args.StdinData, conf); err != nil {
		return nil, nil, errors.Wrap(err, "error loading config from args")
	}

	// args from a string in the form "K=V;K2=V2;..."
	// we added args like region-id/vpc-id/subnet-id
	k8sConfig := types2.K8SArgs{}
	if err = cniTypes.LoadArgs(args.Args, &k8sConfig); err != nil {
		return nil, nil, errors.Wrap(err, "error loading config from args")
	}

	return conf, &k8sConfig, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCniTimeout)
	defer cancel()

	// parse config from args
	cniConfig, k8sConfig, err := parseCmdArgs(args)
	if err != nil {
		return err
	}
	log.Log.Infof("cmdAdd, cniConfig:%+v, k8sConfig: %+v", cniConfig, k8sConfig)

	// set log level
	if len(cniConfig.LogLevel) != 0 {
		log.Log.SetLogLevel(cniConfig.LogLevel)
	}

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	// load DelegateNetConf
	delegates, err := tryLoadDelegateNetConfFromAnno(ctx, cniConfig, k8sConfig)
	if err != nil {
		return err
	}

	if err = verifyAndCompleteDelegateNetConfForCNIAdd(delegates); err != nil {
		return err
	}

	// save DelegateNetConf to cache dir
	err = saveDelegatesNetConf(args.ContainerID, defaultCNIDir, delegates)
	if err != nil {
		return err
	}

	// Delegate
	var result, tmpResult cniTypes.Result
	var netStatus []*NetworkStatus
	var netInfos []NetNsConfig
	setDefaultRoute := false
	for idx, d := range delegates {
		ifName := getIfName(d, args.IfName)
		// build runtimeConf
		rt, cErr := createCNIRuntimeConf(args, k8sConfig, cniConfig, d, ifName)
		if cErr != nil {
			return cErr
		}

		log.Log.Infof("add Delegate, name:%s, ifName:%s, index:%d", d.Name, ifName, d.Index)
		tmpResult, err = DelegateAdd(rt, d, cniConfig)
		if err != nil {
			log.Log.Errorf("add Delegate error, err:%s, name:%s, ifName:%s, index:%d", err.Error(), d.Name, ifName, d.Index)
			_ = delPlugins(args, k8sConfig, cniConfig, delegates, idx)
			return err
		}

		// Master plugin result is always used if present
		if idx == 0 || result == nil {
			result = tmpResult
		}

		// collect network status
		delegateNetStatus, createErr := createNetworkStatus(tmpResult, d)
		if createErr != nil {
			return fmt.Errorf("error setting network status: %v", createErr)
		}

		netStatus = append(netStatus, delegateNetStatus)

		// construct NetNsConfigs
		res, resErr := cni100.NewResultFromResult(tmpResult)
		if resErr != nil {
			log.Log.Errorf("DelegateAdd: error converting result: %v", resErr)
			return fmt.Errorf("DelegateAdd: error converting result: %v", resErr)
		}
		netInfo := NetNsConfig{
			Ips:         []*cni100.IPConfig{},
			ExtraRoutes: []Route{},
		}
		netInfo.DeviceName = ifName
		netInfo.TableId = defaultTableBase + idx
		netInfo.Ips = append(netInfo.Ips, res.IPs...)

		if d.PodNetwork.Traffic != nil {
			if len(d.PodNetwork.Traffic.Routes.ExtraRoutes) != 0 {
				log.Log.Infof("add traffic route, name:%s", d.Name)
				netInfo.ExtraRoutes = append(netInfo.ExtraRoutes, d.PodNetwork.Traffic.Routes.ExtraRoutes...)
			}

			if !setDefaultRoute && d.PodNetwork.Traffic.Routes.IsDefault {
				netInfo.DefaultRoute = true
				setDefaultRoute = true
			}
		}

		netInfos = append(netInfos, netInfo)
	}

	// multi cni need config needed route
	if len(delegates) > 1 {
		// not set default route, just set firs one
		if !setDefaultRoute {
			netInfos[0].DefaultRoute = true
		}
		err = setupRoutes(args.Netns, netInfos)
		if err != nil {
			return err
		}
	}

	if patchStatus {
		log.Log.Infof("patch status:%+v", netStatus)
		// call rpc to patch network status
		start := time.Now()
		if err = patchNetworkStatus(ctx, k8sConfig, netStatus); err != nil {
			return err
		}
		duration := metrics.MsSince(start)
		log.Log.Debugf("patchNetworkStatus time cost:%f Millisecond", duration)
	}

	return result.Print()
}

func setupRoutes(nsname string, netInfos []NetNsConfig) error {
	netNs, err := ns.GetNS(nsname)
	if err != nil {
		return err
	}
	log.Log.Infof("setup Routes, NetNsConfig:%+v", netInfos)

	customRoutes := make(map[string][]RealRoute)

	for _, netInfo := range netInfos {
		var tmpLink netlink.Link
		var ipv4Gw, ipv6Gw net.IP
		err = netNs.Do(func(netNS ns.NetNS) error {
			link, nErr := netlink.LinkByName(netInfo.DeviceName)
			if nErr != nil {
				log.Log.Errorf("link port failed: %s", nErr.Error())
				return err
			}
			tmpLink = link
			routes, nErr := netlink.RouteList(link, netlink.FAMILY_ALL)
			if nErr != nil {
				return fmt.Errorf("unable to list routes: %v", nErr)
			}

			// 1. config policy route
			for _, netIp := range netInfo.Ips {
				family := netlink.FAMILY_V4
				mask := net.CIDRMask(32, 32)
				if utilsnet.IsIPv6(netIp.Address.IP) {
					ipv6Gw = netIp.Gateway
					family = netlink.FAMILY_V6
					mask = net.CIDRMask(128, 128)
				}
				if utilsnet.IsIPv4(netIp.Address.IP) {
					ipv4Gw = netIp.Gateway
				}
				err = netlink.RouteReplace(&netlink.Route{
					LinkIndex: link.Attrs().Index,
					Dst:       nil,
					Family:    family,
					Gw:        net.ParseIP(netIp.Gateway.String()),
					Table:     netInfo.TableId,
				})
				if err != nil {
					log.Log.Errorf("link add ipv4 default route failed:%s", err.Error())
					return err
				}

				// add main src route to policy route
				for i := range routes {
					if netIp.Address.Contains(routes[i].Src) || (routes[i].Src == nil && routes[i].Gw == nil && routes[i].Family == family) {
						routes[i].Table = netInfo.TableId
						// Reset the route flags since if it is dynamically created,
						// adding it to the new table will fail with "invalid argument"
						routes[i].Flags = 0
						// We use route replace in case the route already exists, which
						// is possible for the default gateway we added above.
						rErr := netlink.RouteReplace(&routes[i])
						if rErr != nil {
							return fmt.Errorf("Failed to readd route: %v", err)
						}
					}
				}

				log.Log.Infof("add policy-route, show ip:%s", netIp.Address.String())
				err = netlink.RuleAdd(&netlink.Rule{
					Src: &net.IPNet{
						IP:   netIp.Address.IP,
						Mask: mask,
					},
					SuppressIfgroup:   -1,
					SuppressPrefixlen: -1,
					Mark:              -1,
					Mask:              -1,
					Goto:              -1,
					Flow:              -1,
					Family:            unix.AF_INET,
					Priority:          20000,
					Table:             netInfo.TableId,
				})
				if err != nil {
					log.Log.Errorf("link add ipv4 rule failed:%s", err.Error())
					return err
				}
			}

			// 2. config default route
			if netInfo.DefaultRoute {
				for _, netIp := range netInfo.Ips {
					family := netlink.FAMILY_V4
					if utilsnet.IsIPv6(netIp.Address.IP) {
						family = netlink.FAMILY_V6
					}
					err = netlink.RouteReplace(&netlink.Route{
						LinkIndex: link.Attrs().Index,
						Scope:     netlink.SCOPE_UNIVERSE,
						Dst:       nil,
						Gw:        net.ParseIP(netIp.Gateway.String()),
						Family:    family,
					})
					if err != nil && !os.IsExist(err) {
						log.Log.Errorf("set default route failed:%s", err.Error())
						return fmt.Errorf("set default route failed: %v", err)
					}
				}
			} else {
				// del not default route
				for _, netIp := range netInfo.Ips {
					family := netlink.FAMILY_V4
					if utilsnet.IsIPv6(netIp.Address.IP) {
						family = netlink.FAMILY_V6
					}
					_ = netlink.RouteDel(&netlink.Route{
						LinkIndex: link.Attrs().Index,
						Scope:     netlink.SCOPE_UNIVERSE,
						Dst:       nil,
						Gw:        net.ParseIP(netIp.Gateway.String()),
						Family:    family,
					})
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		for _, route := range netInfo.ExtraRoutes {
			realRoute := RealRoute{}
			_, ipSet, parseErr := net.ParseCIDR(route.Dst)
			if parseErr != nil {
				log.Log.Errorf("parse dst:%s error:%s", route.Dst, parseErr.Error())
				return fmt.Errorf("parse dst error, dst:%s, err:%s", route.Dst, parseErr.Error())
			}
			cidr := route.Dst
			var gw net.IP
			if len(route.Gw) != 0 {
				gw = net.ParseIP(route.Gw)
				if gw == nil {
					log.Log.Errorf("gw:%s ParseIP error", route.Gw)
					return fmt.Errorf("gw:%s ParseIP error", route.Gw)
				}
			}
			if gw == nil && utilsnet.IsIPv4(ipSet.IP) && ipv4Gw != nil {
				gw = ipv4Gw
			}
			if gw == nil && utilsnet.IsIPv6(ipSet.IP) && ipv6Gw != nil {
				gw = ipv6Gw
			}

			if gw == nil {
				gw = cniIp.NextIP(ipSet.IP)
				if gw == nil {
					return fmt.Errorf("gw is nil")
				}
			}
			realRoute.Dst = ipSet
			realRoute.Gw = gw
			realRoute.Dev = tmpLink
			realRoute.TableId = netInfo.TableId

			// TODO support ecmp
			customRoutes[cidr] = []RealRoute{realRoute}
		}
	}

	// 3. config custom route
	err = netNs.Do(func(netNS ns.NetNS) error {
		for cidr, routes := range customRoutes {
			r := routes[0]
			family := netlink.FAMILY_V4
			if utilsnet.IsIPv6(r.Dst.IP) {
				family = netlink.FAMILY_V6
			}
			if len(routes) == 1 {
				log.Log.Infof("add ExtraRoute:%s, gw:%s", cidr, r.Gw.String())
				rt := &netlink.Route{
					LinkIndex: r.Dev.Attrs().Index,
					Scope:     netlink.SCOPE_UNIVERSE,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        r.Gw,
					Dst:       r.Dst,
					Family:    family,
				}

				if replaceErr := netlink.RouteReplace(rt); replaceErr != nil {
					if !os.IsExist(replaceErr) {
						log.Log.Errorf("add route(dst:%s) error:%s", cidr, replaceErr.Error())
						return replaceErr
					}
				}
				if r.TableId > 0 {
					err = netlink.RouteReplace(&netlink.Route{
						LinkIndex: r.Dev.Attrs().Index,
						Scope:     netlink.SCOPE_UNIVERSE,
						Flags:     int(netlink.FLAG_ONLINK),
						Gw:        r.Gw,
						Dst:       r.Dst,
						Table:     r.TableId,
						Family:    family,
					})
					if err != nil {
						log.Log.Errorf("add route  failed:%s", err.Error())
						return err
					}
				}
			}
		}
		return nil
	})
	return nil
}

func saveDelegatesNetConf(containerID, dataDir string, delegates []*DelegateNetConf) error {
	delegatesBytes, err := json.Marshal(delegates)
	if err != nil {
		return fmt.Errorf("saveDelegates: error serializing delegate netconf: %v", err)
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("saveScratchNetConf: failed to create the multus data directory(%q): %v", dataDir, err)
	}

	path := filepath.Join(dataDir, containerID)

	err = os.WriteFile(path, delegatesBytes, 0600)
	if err != nil {
		return fmt.Errorf("saveScratchNetConf: failed to write container data in the path(%q): %v", path, err)
	}
	return err
}

func tryLoadDelegateNetConfFromAnno(ctx context.Context, cniConfig *MetaNetConf, k8sConfig *types2.K8SArgs) ([]*DelegateNetConf, error) {
	// get Pod annotation
	var err error
	var podAnno map[string]string
	if len(cniConfig.RuntimeConfig.PodAnnotations) != 0 {
		podAnno = cniConfig.RuntimeConfig.PodAnnotations
	} else {
		// call cello client to get pod annotation
		err = loadCelloClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("meta addCmd create cello rpc client failed: %w", err)
		}

		// TODO wait for pod-networks annotation
		log.Log.Infof("call celloClient GetPodMetaInfo rpc method")
		response, getErr := celloClient.GetPodMetaInfo(ctx, &pbrpc.GetPodMetaRequest{
			Name:             string(k8sConfig.K8S_POD_NAME),
			Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
			InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
		})
		if getErr != nil {
			if strings.Contains(getErr.Error(), "not found") {
				log.Log.Infof("pod no found")
				return []*DelegateNetConf{}, nil
			}
			return nil, fmt.Errorf("cello GetPodMetaInfo from daemon failed: %w", getErr)
		}
		podAnno = response.GetAnnotations()
	}

	// check podnetworkdefinition have podnetworks
	realPodNetworks := getDefaultPodNetworks(cniConfig)
	var podNetworks []*PodNetwork
	// 1. first check if pod's annotation have pod-networks-definition
	if len(podAnno) != 0 && len(podAnno[podNetworkDefinitionKey]) != 0 {
		log.Log.Infof("load annotation, podNetworksDefinitions:%s, podNetworks:%s",
			podAnno[podNetworkDefinitionKey], podAnno[PodNetworksKey])
		podNetworksDefinitions := make([]*PodNetworkDefinition, 0)
		if err = json.Unmarshal([]byte(podAnno[podNetworkDefinitionKey]), &podNetworksDefinitions); err != nil {
			return nil, fmt.Errorf("unmarshal PodNetworkDefinition failed:%w", err)
		}
		if len(podAnno[PodNetworksKey]) == 0 {
			return nil, fmt.Errorf("PodNetwork is nil, just waiting")
		}

		podNetworks = make([]*PodNetwork, 0)
		if err = json.Unmarshal([]byte(podAnno[PodNetworksKey]), &podNetworks); err != nil {
			return nil, fmt.Errorf("unmarshal PodNetwork failed:%w", err)
		}
		if !matchPodNetworkDefinitionAndPodNetwork(podNetworksDefinitions, podNetworks) {
			return nil, fmt.Errorf("match PodNetworkDefinition error, please wait")
		}
	} else if len(podAnno) != 0 && len(podAnno[PodNetworksKey]) != 0 {
		// 2. support user define pod's annotation pod-networks annotation directly
		podNetworks = make([]*PodNetwork, 0)
		if err = json.Unmarshal([]byte(podAnno[PodNetworksKey]), &podNetworks); err != nil {
			return nil, fmt.Errorf("unmarshal PodNetwork failed:%w", err)
		}

		// validate pod-networks
		if err = verifyPodNetworks(podNetworks); err != nil {
			return nil, err
		}
	}

	if len(podNetworks) != 0 {
		// if define master interface,
		if podNetworks[0].Master {
			realPodNetworks = podNetworks
		} else {
			// if no define, use local default master interface
			realPodNetworks = append(realPodNetworks, podNetworks...)
		}
		patchStatus = true
	}

	// load Delegate from local or crd
	delegates := make([]*DelegateNetConf, 0)
	for idx, pn := range realPodNetworks {
		dnf, loadErr := loadDelegateNetConf(string(k8sConfig.K8S_POD_NAMESPACE), string(k8sConfig.K8S_POD_NAME), pn)
		if loadErr != nil {
			return nil, loadErr
		}
		dnf.Index = idx
		delegates = append(delegates, dnf)
	}

	return delegates, nil
}

func verifyPodNetworks(podNetworks []*PodNetwork) error {
	if len(podNetworks) == 0 {
		return nil
	}
	// check  cni conf config
	var errorstrings []string
	for idx, network := range podNetworks {
		if network.CniConf == nil {
			errorstrings = append(errorstrings, fmt.Sprintf("No.%d cni conf is nil", idx+1))
			continue
		}
		if len(network.CniConf.Name) == 0 {
			errorstrings = append(errorstrings, fmt.Sprintf("No.%d cni conf name is nil", idx+1))
		}
	}
	if len(errorstrings) > 0 {
		return fmt.Errorf(strings.Join(errorstrings, " / "))
	}
	return nil
}

func verifyAndCompleteDelegateNetConfForCNIAdd(ds []*DelegateNetConf) error {
	for _, d := range ds {
		if len(d.MetaRequest.IPRangesSource) != 0 && len(d.MetaConfig.IPRanges) == 0 {
			return fmt.Errorf("delegate %s request ipRanges but got empty", d.Name)
		}
		if len(d.MetaRequest.ResourceName) != 0 && len(d.MetaConfig.DeviceID) == 0 {
			return fmt.Errorf("delegate %s request resource %s deviceID, bug got empty", d.Name, d.MetaRequest.ResourceName)
		}
	}

	return nil
}

func verifyAndCompleteDelegateNetConfForCNIDel(ds []*DelegateNetConf) error {
	for _, d := range ds {
		if len(d.MetaRequest.IPRangesSource) != 0 && len(d.MetaConfig.IPRanges) == 0 {
			_, fake, _ := net.ParseCIDR(fakeIPRangesForDelete)
			log.Log.Infof("Inject fake ipRanges %s for delegate %s ipRangesSource %s to delete", fake, d.Name, d.MetaRequest.IPRangesSource)
			d.MetaConfig.IPRanges = append(d.MetaConfig.IPRanges, RangeSet{
				{
					Subnet: cniTypes.IPNet(*fake),
				},
			})
		}
	}

	return nil
}

func createNetworkStatus(r cniTypes.Result, delegate *DelegateNetConf) (*NetworkStatus, error) {
	// Convert whatever the IPAM result was into the current Result type
	result, err := cni100.NewResultFromResult(r)
	if err != nil {
		return nil, fmt.Errorf("error convert the type.Result to cni100.Result: %v", err)
	}

	netStatus := &NetworkStatus{}
	netStatus.CNIName = delegate.PodNetwork.CniConf.Name

	for _, ifs := range result.Interfaces {
		// Only pod interfaces can have sandbox information
		if ifs.Sandbox != "" {
			netStatus.DeviceInfo.IfName = ifs.Name
			netStatus.DeviceInfo.Mac = ifs.Mac
		}
	}

	for _, ipconfig := range result.IPs {
		netStatus.DeviceInfo.IPs = append(netStatus.DeviceInfo.IPs, ipconfig.Address.IP.String())
	}

	return netStatus, nil
}

func patchNetworkStatus(ctx context.Context, k8sArgs *types2.K8SArgs, netStatus []*NetworkStatus) error {
	if len(netStatus) == 0 {
		log.Log.Infof("netStatus is nil")
		return nil
	}

	var err error
	var networkStatus []string
	for _, status := range netStatus {
		data, jsonErr := json.MarshalIndent(status, "", "    ")
		if jsonErr != nil {
			return fmt.Errorf("SetNetworkStatus: error with Marshal Indent: %v", err)
		}
		networkStatus = append(networkStatus, string(data))
	}

	// call rpc to patch network status
	err = loadCelloClient(ctx)
	if err != nil {
		return fmt.Errorf("meta addCmd create cello rpc client failed: %w", err)
	}

	log.Log.Infof("call celloClient PatchPodAnnotation rpc method, networkStatus:%+v", networkStatus)
	_, err = celloClient.PatchPodAnnotation(ctx, &pbrpc.PatchPodAnnotationRequest{
		Name:      string(k8sArgs.K8S_POD_NAME),
		Namespace: string(k8sArgs.K8S_POD_NAMESPACE),
		Annotations: map[string]string{
			networkStatusKey: fmt.Sprintf("[%s]", strings.Join(networkStatus, ",")),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func DelegateAdd(rt *libcni.RuntimeConf, delegate *DelegateNetConf, netConf *MetaNetConf) (cniTypes.Result, error) {
	// check interface
	if err := validateIfName(rt.NetNS, rt.IfName); err != nil {
		return nil, fmt.Errorf("DelegateAdd: cannot set %q interface name to %q: %v", delegate.Conf.Type, rt.IfName, err)
	}

	var result cniTypes.Result
	var err error
	if delegate.ConfListPlugin {
		result, err = conflistAdd(rt, delegate, netConf)
		if err != nil {
			return nil, err
		}
	} else {
		result, err = confAdd(rt, delegate, netConf)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func conflistAdd(rt *libcni.RuntimeConf, delegate *DelegateNetConf, netConf *MetaNetConf) (cniTypes.Result, error) {
	// In part, adapted from K8s pkg/kubelet/dockershim/network/cni/cni.go
	binDirs := filepath.SplitList(os.Getenv("CNI_PATH"))
	binDirs = append([]string{defaultBinDir}, binDirs...)
	cniNet := libcni.NewCNIConfigWithCacheDir(binDirs, defaultCNIDir, NewMetaExec())

	// call PreAddNetwork to add some runtimeconfig or change delegate
	err := PreNetworkMetaShimFactorys.PreAddNetwork(rt, delegate)
	if err != nil {
		return nil, err
	}

	confList, err := libcni.ConfListFromBytes(delegate.Bytes)
	if err != nil {
		return nil, fmt.Errorf("conflistAdd: error converting the raw bytes into a conflist: %v", err)
	}

	result, err := cniNet.AddNetworkList(context.Background(), confList, rt)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func confAdd(rt *libcni.RuntimeConf, delegate *DelegateNetConf, netConf *MetaNetConf) (cniTypes.Result, error) {
	// In part, adapted from K8s pkg/kubelet/dockershim/network/cni/cni.go
	binDirs := filepath.SplitList(os.Getenv("CNI_PATH"))
	binDirs = append([]string{defaultBinDir}, binDirs...)
	cniNet := libcni.NewCNIConfigWithCacheDir(binDirs, defaultCNIDir, NewMetaExec())

	// call PreAddNetwork to add some runtimeconfig or change delegate
	err := PreNetworkMetaShimFactorys.PreAddNetwork(rt, delegate)
	if err != nil {
		return nil, err
	}

	conf, err := libcni.ConfFromBytes(delegate.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error in converting the raw bytes to conf: %v", err)
	}

	result, err := cniNet.AddNetwork(context.Background(), conf, rt)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func validateIfName(nsname string, ifname string) error {
	podNs, err := ns.GetNS(nsname)
	if err != nil {
		return fmt.Errorf("validateIfName: no net namespace %s found: %v", nsname, err)
	}
	err = podNs.Do(func(_ ns.NetNS) error {
		_, getErr := netlink.LinkByName(ifname)
		if getErr != nil {
			if getErr.Error() == "Link not found" {
				return nil
			}
			return getErr
		}
		return fmt.Errorf("validateIfName: interface name %s already exists", ifname)
	})

	return err
}

func createCNIRuntimeConf(args *skel.CmdArgs, k8sArgs *types2.K8SArgs, netConf *MetaNetConf, d *DelegateNetConf, ifName string) (*libcni.RuntimeConf, error) {
	rc := &libcni.RuntimeConf{
		ContainerID: args.ContainerID,
		NetNS:       args.Netns,
		IfName:      ifName,
		// NOTE: Verbose logging depends on this order, so please keep Args order.
		Args: [][2]string{
			{"IgnoreUnknown", "true"},
			{"K8S_POD_NAMESPACE", string(k8sArgs.K8S_POD_NAMESPACE)},
			{"K8S_POD_NAME", string(k8sArgs.K8S_POD_NAME)},
			{"K8S_POD_INFRA_CONTAINER_ID", string(k8sArgs.K8S_POD_INFRA_CONTAINER_ID)},
			{"K8S_POD_UID", string(k8sArgs.K8S_POD_UID)},
		},
	}
	runtimeConfig := &RuntimeConfig{}
	if d.Index == 0 {
		// just master plugin use runtimeConfig from runtime
		if err := mergeRuntimeConfig(runtimeConfig, &netConf.RuntimeConfig); err != nil {
			return nil, err
		}
	}
	dc, dErr := delegateRuntimeConfig(d)
	if dErr != nil {
		return nil, dErr
	}
	if err := mergeRuntimeConfig(runtimeConfig, dc); err != nil {
		return nil, err
	}
	rc.CapabilityArgs = buildCapabilityArgs(runtimeConfig)

	log.Log.Infof("Create cni runtimeConf: %+v", rc)
	return rc, nil
}

// delegateRuntimeConfig creates the CNI `RuntimeConf` for the given ADD / DEL request.
func delegateRuntimeConfig(delegate *DelegateNetConf) (*RuntimeConfig, error) {
	dc := &RuntimeConfig{}
	if len(delegate.MetaConfig.DeviceID) != 0 {
		dc.DeviceID = delegate.MetaConfig.DeviceID
	}
	if len(delegate.MetaConfig.IPRanges) != 0 {
		dc.IPRanges = delegate.MetaConfig.IPRanges
	}

	if delegate.PodNetwork != nil && delegate.PodNetwork.DeviceConf != nil {
		if len(delegate.PodNetwork.DeviceConf.Mac) != 0 {
			dc.Mac = delegate.PodNetwork.DeviceConf.Mac
		}
		if len(delegate.PodNetwork.DeviceConf.IPs) != 0 {
			for _, ip := range delegate.PodNetwork.DeviceConf.IPs {
				tmpIP := cniIp.ParseIP(ip)
				if tmpIP == nil {
					return nil, fmt.Errorf(fmt.Sprintf("Parse DeviceConf IPs error, ip:%s", ip))
				}
				if dc.IPs == nil {
					dc.IPs = []*cniIp.IP{}
				}
				dc.IPs = append(dc.IPs, tmpIP)
			}
		}
		if delegate.PodNetwork.DeviceConf.Options != nil && len(delegate.PodNetwork.DeviceConf.Options[RuntimeConfigOptionVlanID]) > 0 {
			dc.NetworkInterfaceConfig = &types2.NetworkInterfaceConfig{
				Type: types2.NetworkInterfaceConfigTypeTrunk,
				IPs:  dc.IPs,
				Mac:  dc.Mac,
				Trunk: &types2.NetworkInterfaceTrunkConfig{
					VlanID:   delegate.PodNetwork.DeviceConf.Options[RuntimeConfigOptionVlanID],
					TrunkMac: delegate.PodNetwork.DeviceConf.Options[RuntimeConfigOptionTrunkMac],
				},
			}
		}
	}
	return dc, nil
}

func mergeRuntimeConfig(base *RuntimeConfig, config *RuntimeConfig) error {
	if len(config.PortMaps) != 0 {
		if len(base.PortMaps) != 0 && !reflect.DeepEqual(config.PortMaps, base.PortMaps) {
			return fmt.Errorf("portmap runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.PortMaps = config.PortMaps
	}
	if config.Bandwidth != nil {
		if base.Bandwidth != nil && !reflect.DeepEqual(config.Bandwidth, base.Bandwidth) {
			return fmt.Errorf("bandwidth runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.Bandwidth = config.Bandwidth
	}
	if len(config.PodAnnotations) != 0 {
		if len(base.PodAnnotations) != 0 && !reflect.DeepEqual(config.PodAnnotations, base.PodAnnotations) {
			return fmt.Errorf("io.kubernetes.cri.pod-annotations runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.PodAnnotations = config.PodAnnotations
	}
	if len(config.DeviceID) != 0 {
		if len(base.DeviceID) != 0 && !reflect.DeepEqual(config.DeviceID, base.DeviceID) {
			return fmt.Errorf("deviceID runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.DeviceID = config.DeviceID
	}
	if len(config.IPRanges) != 0 {
		if len(base.IPRanges) != 0 && !reflect.DeepEqual(config.IPRanges, base.IPRanges) {
			return fmt.Errorf("ipRanges runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.IPRanges = config.IPRanges
	}

	if len(config.Mac) != 0 {
		if len(base.Mac) != 0 && !reflect.DeepEqual(config.Mac, base.Mac) {
			return fmt.Errorf("mac runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.Mac = config.Mac
	}

	if len(config.IPs) != 0 {
		if len(base.IPs) != 0 && !reflect.DeepEqual(config.IPs, base.IPs) {
			return fmt.Errorf("ips runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.IPs = config.IPs
	}

	if config.NetworkInterfaceConfig != nil {
		if base.NetworkInterfaceConfig != nil && !reflect.DeepEqual(config.NetworkInterfaceConfig, base.NetworkInterfaceConfig) {
			return fmt.Errorf("com.volcengine.k8s.network-interface runtimeConfig confilict, base: %v, new: %v", base, config)
		}
		base.NetworkInterfaceConfig = config.NetworkInterfaceConfig
	}
	return nil
}

func buildCapabilityArgs(config *RuntimeConfig) map[string]interface{} {
	capabilityArgs := map[string]interface{}{}
	if len(config.PortMaps) != 0 {
		capabilityArgs["portMappings"] = config.PortMaps
	}
	if config.Bandwidth != nil {
		capabilityArgs["bandwidth"] = config.Bandwidth
	}
	if len(config.PodAnnotations) != 0 {
		capabilityArgs["io.kubernetes.cri.pod-annotations"] = config.PodAnnotations
	}
	if len(config.DeviceID) != 0 {
		capabilityArgs["deviceID"] = config.DeviceID
	}
	if len(config.IPRanges) != 0 {
		capabilityArgs["ipRanges"] = config.IPRanges
	}
	if len(config.Mac) != 0 {
		capabilityArgs["mac"] = config.Mac
	}
	if len(config.IPs) != 0 {
		capabilityArgs["ips"] = config.IPs
	}
	if config.NetworkInterfaceConfig != nil {
		capabilityArgs["com.volcengine.k8s.network-interface"] = config.NetworkInterfaceConfig
	}

	return capabilityArgs
}

func getIfName(delegate *DelegateNetConf, argif string) string {
	if delegate.Index == 0 {
		// master plugin always uses the CNI-provided interface name
		return argif
	}
	if delegate.PodNetwork.DeviceConf != nil && delegate.PodNetwork.DeviceConf.IfName != "" {
		return delegate.PodNetwork.DeviceConf.IfName
	}
	// Otherwise construct a unique interface name from the delegate's
	// position in the delegate list
	return fmt.Sprintf("eth%d", delegate.Index)
}

func loadDelegateNetConf(podNamespace, podName string, pn *PodNetwork) (*DelegateNetConf, error) {
	if pn.CniConf == nil {
		return nil, fmt.Errorf("PodNetwork CniConf is nil, ns:%s, name:%s", pn.Namespace, pn.Name)
	}

	var bytes []byte
	// TODO: support cniConf from crd
	if pn.CniConf.From == cniConfLocal || pn.CniConf.From == "" {
		if len(pn.CniConf.Name) == 0 {
			return nil, fmt.Errorf("PodNetwork CniConf name is nil, ns:%s, name:%s", pn.Namespace, pn.Name)
		}
		bytesTmp, err := netutils.GetCNIConfigFromFile(pn.CniConf.Name, cniConfDir)
		if err != nil {
			return nil, err
		}
		bytes = bytesTmp
	} else {
		return nil, fmt.Errorf("no support cni conf no local")
	}

	delegateConf := &DelegateNetConf{}
	if err := json.Unmarshal(bytes, &delegateConf.Conf); err != nil {
		return nil, fmt.Errorf("loadDelegateNetConf: error unmarshalling delegate config: %v", err)
	}
	delegateConf.Name = delegateConf.Conf.Name
	delegateConf.MetaRequest = delegateConf.Conf.MetaRequest
	if delegateConf.Conf.Type == "" {
		if err := json.Unmarshal(bytes, &delegateConf.ConfList); err != nil {
			return nil, fmt.Errorf("loadDelegateNetConf: error unmarshalling delegate conflist: %v", err)
		}
		if len(delegateConf.ConfList.Plugins) == 0 {
			return nil, fmt.Errorf("loadDelegateNetConf: delegate must have the 'type' or 'plugin' field")
		}

		if delegateConf.ConfList.Plugins[0].Type == "" {
			return nil, fmt.Errorf("loadDelegateNetConf: a plugin delegate must have the 'type' field")
		}
		delegateConf.ConfListPlugin = true
		delegateConf.Name = delegateConf.ConfList.Name
		delegateConf.MetaRequest = delegateConf.ConfList.MetaRequest
	}

	delegateConf.PodNetwork = pn
	delegateConf.Bytes = bytes

	// build meta dynamic config
	if err := buildMetaConfigForDelegateNetConf(podNamespace, podName, delegateConf); err != nil {
		return nil, err
	}

	log.Log.Debugf("Load DelegateNetConf %v", delegateConf)
	return delegateConf, nil
}

// buildMetaConfigForDelegateNetConf
// NOTICE we ignore some error here, should verify meta config outside before delegate CNIADD/CNIDEL
func buildMetaConfigForDelegateNetConf(podNamespace, podName string, delegate *DelegateNetConf) error {
	if delegate.MetaRequest.ResourceName != "" {
		// get device id from kubelet
		if podName != "" && podNamespace != "" {
			// ResourceName annotation is found; try to get device info from resourceMap
			log.Log.Debugf("Found resourceName annotation : %s", delegate.MetaRequest.ResourceName)
			resourceMap, err := getPodResourceMap(podNamespace, podName)
			if err != nil {
				return fmt.Errorf("get pod resource map failed, %v", err)
			}
			log.Log.Debugf("Got resourceMap instance: %+v", resourceMap)

			entry, ok := resourceMap[delegate.MetaRequest.ResourceName]
			if ok {
				log.Log.Infof("Found device entry: %+v", entry)
				if idCount := len(entry.DeviceIDs); idCount > 0 && idCount > entry.Index {
					delegate.MetaConfig.DeviceID = entry.DeviceIDs[entry.Index]
					log.Log.Infof("Got podName: %s deviceID: %s", podName, delegate.MetaConfig.DeviceID)
					entry.Index++ // increment Index for next delegate
				}
			}
		}
	}
	if delegate.MetaRequest.IPRangesSource != "" {
		// get ip ranges
		switch IPRangeSourceType(delegate.MetaRequest.IPRangesSource) {
		case IpRangeSourceNetDeviceSubnet, IPRangeSourceNetDeviceSelf:
			if delegate.MetaConfig.DeviceID == "" {
				// todo: support get device id from other config
				log.Log.Errorf("Delegate meta ipRangesSource got device id empty, ignore")
				break
			}
			var err error
			if delegate.MetaConfig.IPRanges, err = getIpRangesFromNetDevice(delegate.MetaConfig.DeviceID, delegate.MetaRequest.IPRangesSource); err != nil {
				return fmt.Errorf("delegate meta ipRangeSource got from device %s failed, %v", delegate.MetaConfig.DeviceID, err)
			}
		case IPRangeSourceNone:
		default:
			log.Log.Errorf("Delegate meta ipRangesSource unknown: %s, ignored", delegate.MetaRequest.IPRangesSource)
		}
	}

	return nil
}

// cache pod resource map, not threadsafe
var cache map[string]*types2.ResourceInfo

// getPodResourceMap return pod resource map from kubelet
// cache result every CNIADD/CNIDEL binary exec and auto release binary exit
// NOTICE: not threadsafe
func getPodResourceMap(podNamespace, podName string) (map[string]*types2.ResourceInfo, error) {
	if cache != nil {
		return cache, nil
	}
	ck, err := client2.GetResourceClient("")
	if err != nil {
		return nil, fmt.Errorf("failed to get a ResourceClient instance: %v", err)
	}
	resourceMap, err := ck.GetPodResourceMap(podNamespace, podName)
	if err != nil {
		return nil, fmt.Errorf("failed to get resourceMap from ResourceClient: %v", err)
	}
	cache = resourceMap

	return resourceMap, nil
}

// matchPodNetworkDefinitionAndPodNetwork return
// - true, match success
// - false match failed
func matchPodNetworkDefinitionAndPodNetwork(pnds []*PodNetworkDefinition, pns []*PodNetwork) bool {
	if len(pnds) == 0 || len(pns) == 0 || len(pnds) != len(pns) {
		return false
	}

	for idx, pnd := range pnds {
		if pns[idx].Namespace != pnd.Namespace || pns[idx].Name != pnd.Name {
			return false
		}
	}
	return true
}

func CmdDel(args *skel.CmdArgs) error {
	return cmdDel(args)
}

func cmdDel(args *skel.CmdArgs) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCniTimeout)
	defer cancel()

	// parse config from args
	cniConfig, k8sConfig, err := parseCmdArgs(args)
	if err != nil {
		return err
	}

	// set log level
	if len(cniConfig.LogLevel) != 0 {
		log.Log.SetLogLevel(cniConfig.LogLevel)
	}

	log.Log.Infof("cmdDel, cniConfig:%+v, k8sConfig: %+v", cniConfig, k8sConfig)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	// load DelegateNetConf
	var delegates []*DelegateNetConf
	delegates, err = tryLoadDelegateNetConfFromCache(args.ContainerID, defaultCNIDir)
	if err != nil {
		log.Log.Infof("try LoadDelegateNetConf From Cache error, err:%s", err.Error())
	}

	if len(delegates) == 0 {
		delegates, err = tryLoadDelegateNetConfFromAnno(ctx, cniConfig, k8sConfig)
		if err != nil {
			_, osErr := os.Stat(filepath.Join(args.ContainerID, defaultCNIDir))
			if osErr != nil && os.IsNotExist(osErr) {
				return nil
			}
			return err
		}
	}

	if err = verifyAndCompleteDelegateNetConfForCNIDel(delegates); err != nil {
		return err
	}

	err = delPlugins(args, k8sConfig, cniConfig, delegates, len(delegates)-1)
	if err != nil {
		return err
	}

	path := filepath.Join(defaultCNIDir, args.ContainerID)
	log.Log.Infof("cmdDel, del path:%s", path)
	_ = os.Remove(path)

	return nil
}

func delPlugins(args *skel.CmdArgs, k8sArgs *types2.K8SArgs, netConf *MetaNetConf, delegates []*DelegateNetConf, lastIdx int) error {
	var errorstrings []string
	for idx := lastIdx; idx >= 0; idx-- {
		ifName := getIfName(delegates[idx], args.IfName)
		rt, err := createCNIRuntimeConf(args, k8sArgs, netConf, delegates[idx], ifName)
		if err != nil {
			errorstrings = append(errorstrings, err.Error())
			continue
		}
		log.Log.Infof("DelegateDel, name:%s, ifName:%s, index:%d", delegates[idx].Name, ifName, idx)
		// Attempt to delete all but do not error out, instead, collect all errors.
		if err = DelegateDel(rt, delegates[idx], netConf); err != nil {
			log.Log.Infof("DelegateDel error, err:%s, name:%s, ifName:%s, index:%d", err.Error(), delegates[idx].Name, ifName, idx)
			errorstrings = append(errorstrings, err.Error())
		}
	}

	// Check if we had any errors, and send them all back.
	if len(errorstrings) > 0 {
		return fmt.Errorf(strings.Join(errorstrings, " / "))
	}

	return nil
}

func DelegateDel(rt *libcni.RuntimeConf, delegate *DelegateNetConf, netConf *MetaNetConf) error {
	var err error
	if delegate.ConfListPlugin {
		err = conflistDel(rt, delegate, netConf)
		if err != nil {
			return fmt.Errorf("DelegateDel: error invoking ConflistDel - %q: %v", delegate.ConfList.Name, err)
		}
	} else {
		err = confDel(rt, delegate, netConf)
		if err != nil {
			return fmt.Errorf("DelegateDel: error invoking DelegateDel - %q: %v", delegate.Conf.Type, err)
		}
	}
	return err
}

func conflistDel(rt *libcni.RuntimeConf, delegate *DelegateNetConf, netConf *MetaNetConf) error {
	// In part, adapted from K8s pkg/kubelet/dockershim/network/cni/cni.go
	binDirs := filepath.SplitList(os.Getenv("CNI_PATH"))
	binDirs = append([]string{defaultBinDir}, binDirs...)
	cniNet := libcni.NewCNIConfigWithCacheDir(binDirs, defaultCNIDir, NewMetaExec())

	// call PreAddNetwork to add some runtimeconfig or change delegate
	err := PreNetworkMetaShimFactorys.PreDelNetwork(rt, delegate)
	if err != nil {
		return err
	}

	confList, err := libcni.ConfListFromBytes(delegate.Bytes)
	if err != nil {
		return fmt.Errorf("conflistDel: error converting the raw bytes into a conflist: %v", err)
	}

	err = cniNet.DelNetworkList(context.Background(), confList, rt)
	if err != nil {
		return fmt.Errorf("conflistDel: error in getting result from DelNetworkList: %v", err)
	}

	return err
}

func confDel(rt *libcni.RuntimeConf, delegate *DelegateNetConf, netConf *MetaNetConf) error {
	// In part, adapted from K8s pkg/kubelet/dockershim/network/cni/cni.go
	binDirs := filepath.SplitList(os.Getenv("CNI_PATH"))
	binDirs = append([]string{defaultBinDir}, binDirs...)
	cniNet := libcni.NewCNIConfigWithCacheDir(binDirs, defaultCNIDir, NewMetaExec())

	// call PreAddNetwork to add some runtimeconfig or change delegate
	err := PreNetworkMetaShimFactorys.PreDelNetwork(rt, delegate)
	if err != nil {
		return err
	}

	conf, err := libcni.ConfFromBytes(delegate.Bytes)
	if err != nil {
		return fmt.Errorf("error in converting the raw bytes to conf: %v", err)
	}

	err = cniNet.DelNetwork(context.Background(), conf, rt)
	if err != nil {
		return fmt.Errorf("error in getting result from DelNetwork: %v", err)
	}
	return err
}

func tryLoadDelegateNetConfFromCache(containerID, dataDir string) ([]*DelegateNetConf, error) {
	path := filepath.Join(dataDir, containerID)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	netConf := []*DelegateNetConf{}
	if err = json.Unmarshal(b, &netConf); err != nil {
		return nil, err
	}
	return netConf, nil
}
