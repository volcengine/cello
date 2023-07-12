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

	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/plugins/client/grpc"
	"github.com/volcengine/cello/pkg/plugins/driver"
	"github.com/volcengine/cello/pkg/plugins/log"
	"github.com/volcengine/cello/pkg/plugins/types"
	"github.com/volcengine/cello/pkg/plugins/utils"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/pkg/utils/logger"
	celloTypes "github.com/volcengine/cello/types"
)

const (
	defaultCniTimeout = 120 * time.Second
	defaultVethPrefix = "cel"
)

var lg = log.Log.WithFields(logger.Fields{"component": "cello CNI"})

// CmdAdd calls InternalAdd to set up network for netns.
func CmdAdd(args *skel.CmdArgs) error {
	result, err := InternalAdd(args)
	if err != nil {
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
	return InternalDel(args)
}

// CmdCheck should probe the status of an existing container.
// cello currently does not support check.
func CmdCheck(_ *skel.CmdArgs) error {
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
	lg.InfoS("show CniConf", "CniConf", cniConfig)

	lg = lg.WithFields(logger.Fields{
		"Namespace":   k8sConfig.K8S_POD_NAMESPACE,
		"Name":        k8sConfig.K8S_POD_NAME,
		"ContainerId": args.ContainerID,
		"Netns":       args.Netns},
	)
	lg.InfoS("Handle cmd add")

	start := time.Now()
	defer func() {
		if err != nil {
			lg.ErrorS(err, "Handle cmd add failed")
		}
		duration := metrics.MsSince(start)
		lg.InfoS("CmdAdd time cost millisecond", "cost", fmt.Sprintf("%f", duration))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), defaultCniTimeout)
	defer cancel()

	celloClient, conn, err := grpc.NewCelloClient(ctx)
	if err != nil {
		err = fmt.Errorf("cello addCmd create cello rpc client failed: %w", err)
		return
	}
	defer func() {
		_ = conn.Close()
	}()

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
	lg.InfoS("Cello create endpoint response", "response", createEndpointResponse.String())

	defer func() {
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
					lg.ErrorS(err, "Request to delete endpoint failed")
				}
			}
		}
	}()

	//setup network
	var network *pbrpc.NetworkInterface
	var networkConfig *types.SetupConfig
	networks := createEndpointResponse.GetInterfaces()
	// TODO: should only support one interface.
	network, err = findNetwork(args.IfName, networks)
	if err != nil {
		return
	}

	networkConfig, err = generateSetupConfig(args, cniConfig, network)
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
	types.AppendNetworkConfigToCNIResult(cniResult, networkConfig)
	cniResultJson, _ := json.Marshal(cniResult)
	lg.DebugS("CNI Result", "result", cniResultJson)
	result = cniResult
	return
}

// InternalDel tears down all the networks in the sandbox.
func InternalDel(args *skel.CmdArgs) error {
	_, cniConfig, k8sConfig, err := parseCmdArgs(args)
	if err != nil {
		lg.ErrorS(err, "Parse cmdArgs failed")
		return err
	}
	lg.Infof("CniConf: %+v", cniConfig)

	lg = lg.WithFields(logger.Fields{
		"Namespace":   k8sConfig.K8S_POD_NAMESPACE,
		"Name":        k8sConfig.K8S_POD_NAME,
		"ContainerId": args.ContainerID,
		"Netns":       args.Netns},
	)
	lg.InfoS("Handle cmd del")

	start := time.Now()
	defer func() {
		if err != nil {
			lg.ErrorS(err, "Handle cmd del failed")
		}
		duration := metrics.MsSince(start)
		lg.InfoS("CmdDel time cost millisecond", "cost", fmt.Sprintf("%f", duration))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), defaultCniTimeout)
	defer cancel()

	celloClient, conn, err := grpc.NewCelloClient(ctx)
	if err != nil {
		return fmt.Errorf("cello cmdDel create cello rpc client failed: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// todo: support delete one of multiple networks
	err = driver.GenericTeardownNetwork(args.Netns)
	if err != nil {
		lg.ErrorS(err, "Teardown driver failed", "PodNamespace", k8sConfig.K8S_POD_NAMESPACE, "PodName", k8sConfig.K8S_POD_NAME, "IfName", args.IfName)
		return nil
	}
	lg.InfoS("Teardown driver success", "PodNamespace", k8sConfig.K8S_POD_NAMESPACE, "PodName", k8sConfig.K8S_POD_NAME, "IfName", args.IfName)

	if cniConfig.RuntimeConfig.NetworkInterfaceConfig == nil {
		deleteEndpointRequest := &pbrpc.DeleteEndpointRequest{
			Name:             string(k8sConfig.K8S_POD_NAME),
			Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
			InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
		}
		_, err = celloClient.DeleteEndpoint(ctx, deleteEndpointRequest)
		if err != nil {
			lg.ErrorS(err, "Request to delete endpoint failed")
			return err
		}
	} // if static ipam, do nothing

	lg.InfoS("Request to delete endpoint succeed")

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

func generateSetupConfig(args *skel.CmdArgs, conf *types.NetConf, network *pbrpc.NetworkInterface) (*types.SetupConfig, error) {
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
		lg.WarnS("Failed to get host addresses", "err", err)
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

	switch network.IfType {
	case pbrpc.IfType_TypeENIShare:
		networkConfig.DP = types.IPVlan
		networkConfig.SetupInitNs = true
	case pbrpc.IfType_TypeENIExclusive:
		networkConfig.DP = types.ENI
	case pbrpc.IfType_TypeENTTrunk:
		networkConfig.DP = types.Vlan
	default:
		return nil, fmt.Errorf("unsupported ipType %d", network.IfType)
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
