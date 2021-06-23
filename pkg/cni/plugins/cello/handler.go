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

package cello

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/040"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/cni/client"
	"github.com/volcengine/cello/pkg/cni/driver"
	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/cni/utils"
	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/pkg/utils/logger"
	celloTypes "github.com/volcengine/cello/types"
)

const (
	defaultCniTimeout = 120 * time.Second
	defaultVethPrefix = "cel"
)

// CmdAdd calls InternalAdd to set up network for netns.
func CmdAdd(args *skel.CmdArgs) error {
	result, err := InternalAdd(args)
	if err != nil {
		log.Log.Errorf("Failed to add: %s", err.Error())
		return err
	}
	err = cniTypes.PrintResult(result, result.Version())
	if err != nil {
		return err
	}
	return nil
}

// CmdDel calls InternalDel to teardown network for netns.
func CmdDel(args *skel.CmdArgs) error {
	err := InternalDel(args)
	if err != nil {
		log.Log.Errorf("Failed to del%s", err.Error())
	}
	return err
}

// CmdCheck should probe the status of an existing container.
// cello currently does not support check.
func CmdCheck(args *skel.CmdArgs) error {
	return nil
}

// InternalAdd VPC network interfaces and configs for sandbox,
// which will request daemon for network configs by default
// unless it has been specified in runtimeConfig.
func InternalAdd(args *skel.CmdArgs) (result cniTypes.Result, err error) {
	_, cniConfig, k8sConfig, err := parseCmdArgs(args)
	if err != nil {
		return
	}
	log.Log.Infof("CniConf: %+v", cniConfig)

	ctx, cancel := context.WithTimeout(context.Background(), defaultCniTimeout)
	defer cancel()

	celloClient, conn, err := client.NewCelloClient(ctx)
	if err != nil {
		err = fmt.Errorf("cello addCmd create cello rpc client failed: %w", err)
		return
	}
	defer conn.Close()

	var createEndpointResponse *pbrpc.CreateEndpointResponse
	if cniConfig.RuntimeConfig.NetworkInterfaceConfig != nil {
		// Load networkConfig from runtimeConfig.
		createEndpointResponse, err = buildEndpointFromNetworkInterfaceConfig(cniConfig, args.IfName)
	} else {
		// Request for networkConfig from local RPC endpoint(cello daemon/IPAM).
		createEndpointRequest := &pbrpc.CreateEndpointRequest{
			Name:             string(k8sConfig.K8S_POD_NAME),
			Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
			InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
			IfName:           args.IfName,
			NetNs:            args.Netns,
		}
		createEndpointResponse, err = celloClient.CreateEndpoint(ctx, createEndpointRequest)
	}
	if err != nil {
		err = fmt.Errorf("cello create endpoint failed: %w", err)
		return
	}
	log.Log.Infof("cello create endpoint response: %s", createEndpointResponse.String())
	start := time.Now()

	defer func() {
		duration := metrics.MsSince(start)
		log.Log.WithFields(logger.Fields{"TimeCost": duration, "Success": err == nil}).Infof("Setup driver for %s/%s",
			k8sConfig.K8S_POD_NAMESPACE, k8sConfig.K8S_POD_NAME)
		if err != nil {
			// TODO: support delete specific network interface.
			if cniConfig.RuntimeConfig.NetworkInterfaceConfig == nil {
				deleteEndpointRequest := &pbrpc.DeleteEndpointRequest{
					Name:             string(k8sConfig.K8S_POD_NAME),
					Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
					InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
				}
				_, err2 := celloClient.DeleteEndpoint(ctx, deleteEndpointRequest)
				if err2 != nil {
					log.Log.Errorf("Request to delete endpoint failed: %s", err.Error())
				}
			}
		}
	}()

	ipType := types.ENIMultiIP
	if createEndpointResponse.IfType == pbrpc.IfType_TypeENIExclusive {
		ipType = types.ENISingleIP
	}

	//setup network
	var network *pbrpc.NetworkInterface
	var networkConfig *types.SetupConfig
	networks := createEndpointResponse.GetInterfaces()
	// TODO: should only support one interface.
	network, err = findNetwork(args.IfName, networks)
	if err != nil {
		return
	}

	networkConfig, err = generateSetupConfig(args, cniConfig, network, ipType)
	if err != nil {
		return nil, fmt.Errorf("parse setupConfig failed, %w", err)
	}
	// TODO: remove integrated multi-interfaces support.
	networkConfig.PolicyRoute = args.IfName != celloTypes.DefaultIfName && len(networks) > 1
	networkConfig.VethNameInHost, _ = utils.VethNameForPod(string(k8sConfig.K8S_POD_NAME), string(k8sConfig.K8S_POD_NAMESPACE), network.IfName, defaultVethPrefix)

	// Setup network for netns.
	err = driver.SetupDataPath(networkConfig)
	if err != nil {
		return
	}

	cniResult := &current.Result{
		CNIVersion: cniVersion.Current(),
		Interfaces: nil,
		IPs:        nil,
		Routes:     nil,
		DNS:        cniTypes.DNS{},
	}
	appendNetworkConfigToCNIResult(cniResult, networkConfig)
	cniResultJson, _ := json.Marshal(cniResult)
	log.Log.Debugf("CNI Result: %s", cniResultJson)
	result = cniResult
	return
}

// InternalDel tears down all the networks in the sandbox.
func InternalDel(args *skel.CmdArgs) error {
	_, cniConfig, k8sConfig, err := parseCmdArgs(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultCniTimeout)
	defer cancel()

	celloClient, conn, err := client.NewCelloClient(ctx)
	if err != nil {
		return fmt.Errorf("cello cmdDel create cello rpc client failed: %w", err)
	}
	defer conn.Close()

	start := time.Now()
	// todo: support delete one of multiple networks
	err = driver.TeardownNetwork(args.Netns)
	duration := metrics.MsSince(start)
	log.Log.WithFields(logger.Fields{"TimeCost": duration, "Netns": args.Netns, "Status": fmt.Sprint(err == nil)}).
		Infof("Teardown driver for %s/%s", k8sConfig.K8S_POD_NAMESPACE, k8sConfig.K8S_POD_NAME)
	if err != nil {
		return err
	}

	if cniConfig.RuntimeConfig.NetworkInterfaceConfig == nil {
		deleteEndpointRequest := &pbrpc.DeleteEndpointRequest{
			Name:             string(k8sConfig.K8S_POD_NAME),
			Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
			InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
		}
		_, err = celloClient.DeleteEndpoint(ctx, deleteEndpointRequest)
		if err != nil {
			log.Log.Errorf("Request to delete endpoint failed: %s", err.Error())
			return err
		}
	} // if static ipam, do nothing

	log.Log.Infof("Request to delete endpoint succeed")

	return nil
}

func parseCmdArgs(args *skel.CmdArgs) (string, *types.NetConf, *types.K8SArgs, error) {
	// get cni request version
	versionDecoder := &cniVersion.ConfigDecoder{}
	confVersion, err := versionDecoder.Decode(args.StdinData)
	if err != nil {
		return "", nil, nil, err
	}

	// parse config in cni conf file
	conf := types.NetConf{}
	if err = json.Unmarshal(args.StdinData, &conf); err != nil {
		return "", nil, nil, errors.Wrap(err, "error loading config from args")
	}

	// args from a string in the form "K=V;K2=V2;..."
	// we added args like region-id/vpc-id/subnet-id
	k8sConfig := types.K8SArgs{}
	if err = cniTypes.LoadArgs(args.Args, &k8sConfig); err != nil {
		return "", nil, nil, errors.Wrap(err, "error loading config from args")
	}

	return confVersion, &conf, &k8sConfig, nil
}

func generateSetupConfig(args *skel.CmdArgs, conf *types.NetConf, network *pbrpc.NetworkInterface, ipType types.IPType) (*types.SetupConfig, error) {
	eniLink, err := iproute.LinkByMac(network.GetENI().GetMac())
	if err != nil {
		return nil, fmt.Errorf("could not found dev [%s-%s]: %w", network.GetENI().ID, network.GetENI().GetMac(), err)
	}

	redirectToHostCIDRs := make([]*net.IPNet, 0)
	for _, cidr := range conf.RedirectToHostCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("redirectToHostCIDRs(%s) is invaild: %w", cidr, err)
		}
		redirectToHostCIDRs = append(redirectToHostCIDRs, ipNet)
	}

	var (
		podIPv4Net  *net.IPNet
		podIPv6Net  *net.IPNet
		gatewayIPv4 net.IP
		gatewayIPv6 net.IP
	)

	getPodIPSet := func(podIP string) (*net.IPNet, error) {
		ip, n, inErr := net.ParseCIDR(podIP)
		if inErr != nil {
			return nil, inErr
		}
		n.IP = ip
		return n, nil
	}

	gatewayIPv4Str := network.GetENI().GetIPv4Gateway()
	gatewayIPv6Str := network.GetENI().GetIPv6Gateway()
	if network.GetIPv4Addr() != "" {
		podIPv4Net, err = getPodIPSet(network.GetIPv4Addr())
		if err != nil {
			return nil, err
		}
	}
	if network.GetIPv6Addr() != "" {
		podIPv6Net, err = getPodIPSet(network.GetIPv6Addr())
		if err != nil {
			return nil, err
		}
	}

	if gatewayIPv4Str != "" {
		gatewayIPv4 = net.ParseIP(gatewayIPv4Str)
		if gatewayIPv4 == nil {
			return nil, fmt.Errorf("failed to parse ip %s", gatewayIPv6Str)
		}
	}

	if gatewayIPv6Str != "" {
		gatewayIPv6 = net.ParseIP(gatewayIPv6Str)
		if gatewayIPv6 == nil {
			return nil, fmt.Errorf("failed to parse ip %s", gatewayIPv6Str)
		}
	}

	hostIPSet, err := iproute.GetHostIP()
	if err != nil {
		log.Log.Warnf("failed to get host addresses: %v", err.Error())
	}

	hostLink, err := iproute.GetHostLinkByDefaultRoute(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("get host link failed: %s", err.Error())
	}

	var slaveMac net.HardwareAddr
	if m := network.GetENI().GetSlaveMac(); m != "" {
		slaveMac, err = net.ParseMAC(network.GetENI().GetSlaveMac())
		if err != nil {
			return nil, err
		}
	}
	networkConfig := &types.SetupConfig{
		ENIIndex:            eniLink.Attrs().Index,
		IfName:              args.IfName,
		NetNSPath:           args.Netns,
		IPv4:                podIPv4Net,
		IPv4Gateway:         gatewayIPv4,
		IPv6:                podIPv6Net,
		IPv6Gateway:         gatewayIPv6,
		BandWidth:           conf.RuntimeConfig.Bandwidth,
		DefaultRoute:        network.DefaultRoute,
		RedirectToHostCIDRs: redirectToHostCIDRs,
		LocalFastPath:       conf.LocalFastPath,
		HostIPSet:           hostIPSet,
		HostLink:            hostLink,
		Vid:                 network.GetENI().GetVid(),
		HardwareAddr:        slaveMac,
	}
	var routes []cniTypes.Route
	for _, r := range network.GetExtraRoutes() {
		ip, n, inErr := net.ParseCIDR(r.Dst)
		if inErr != nil {
			return nil, fmt.Errorf("parse extra routes failed, %w", inErr)
		}
		route := cniTypes.Route{Dst: *n}
		if ip.To4() != nil {
			route.GW = gatewayIPv4
		} else {
			route.GW = gatewayIPv6
		}
		routes = append(routes, route)
	}
	networkConfig.ExtraRoutes = routes

	switch ipType {
	case types.ENIMultiIP:
		networkConfig.DP = types.IPVlan
	case types.ENISingleIP:
		if networkConfig.Vid != 0 {
			networkConfig.DP = types.Vlan
		} else {
			networkConfig.DP = types.ENI
		}
	default:
		return nil, fmt.Errorf("unsupported ipType %d", ipType)
	}

	return networkConfig, nil
}

func findNetwork(ifName string, networks []*pbrpc.NetworkInterface) (*pbrpc.NetworkInterface, error) {
	// TODO: need support multi cni
	for _, n := range networks {
		if n.IfName == ifName {
			return n, nil
		}
		if ifName == celloTypes.DefaultIfName && n.IfName == "" {
			return n, nil
		}
	}
	return nil, fmt.Errorf("not found network for %s", ifName)
}

func appendNetworkConfigToCNIResult(cniResult *current.Result, networkConfig *types.SetupConfig) {
	cniInterface := &current.Interface{
		Name:    networkConfig.IfName,
		Mac:     networkConfig.Link.Attrs().HardwareAddr.String(),
		Sandbox: networkConfig.NetNSPath,
	}
	cniResult.Interfaces = append(cniResult.Interfaces, cniInterface)
	cniIfIndex := len(cniResult.Interfaces) - 1

	if networkConfig.IPv4 != nil && networkConfig.IPv4Gateway != nil {
		cniResult.IPs = append(cniResult.IPs, &current.IPConfig{
			Version:   "4",
			Interface: &cniIfIndex,
			Address:   *networkConfig.IPv4,
			Gateway:   networkConfig.IPv4Gateway,
		})
		cniResult.Routes = append(cniResult.Routes, &cniTypes.Route{
			Dst: net.IPNet{
				IP:   net.ParseIP("0.0.0.0"),
				Mask: net.CIDRMask(0, 32),
			},
			GW: networkConfig.IPv4Gateway,
		})
	}
	if networkConfig.IPv6 != nil && networkConfig.IPv6Gateway != nil {
		cniResult.IPs = append(cniResult.IPs, &current.IPConfig{
			Version:   "6",
			Interface: &cniIfIndex,
			Address:   *networkConfig.IPv6,
			Gateway:   networkConfig.IPv6Gateway,
		})
		cniResult.Routes = append(cniResult.Routes, &cniTypes.Route{
			Dst: net.IPNet{
				IP:   net.ParseIP("::"),
				Mask: net.CIDRMask(0, 128),
			},
			GW: networkConfig.IPv6Gateway,
		})
	}
}
