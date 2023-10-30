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

package cello_rdma

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/040"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"

	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/plugins/client/grpc"
	"github.com/volcengine/cello/pkg/plugins/driver"
	cniLog "github.com/volcengine/cello/pkg/plugins/log"
	"github.com/volcengine/cello/pkg/plugins/types"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/pkg/utils/logger"
	celloTypes "github.com/volcengine/cello/types"
)

var lg = cniLog.Log.WithFields(logger.Fields{"component": "cello-rdma CNI"})

const (
	defaultCniTimeout = 120 * time.Second
)

func CmdAdd(args *skel.CmdArgs) (err error) {
	_, cniConfig, k8sConfig, err := types.ParseCmdArgs(args)
	if err != nil {
		lg.Errorf("parse cmdArgs failed, %v", err)
		return err
	}
	lg.Infof("CniConf: %+v", cniConfig)

	lg = lg.WithFields(logger.Fields{
		"Namespace":   k8sConfig.K8S_POD_NAMESPACE,
		"NetName":     k8sConfig.K8S_POD_NAME,
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
		return fmt.Errorf("cello addCmd create cello rpc client failed: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if cniConfig.RuntimeConfig.DeviceID == "" {
		return fmt.Errorf("no master device")
	}

	var ipamType string
	switch strings.ToLower(cniConfig.DriverType) {
	case strings.ToLower(pbrpc.IfType_TypePhysicsShare.String()):
		ipamType = celloTypes.IPAMTypeRdmaShare
	case strings.ToLower(pbrpc.IfType_TypePhysicsExclusive.String()):
		ipamType = celloTypes.IPAMTypeRdmaExclusive
	default:
		return fmt.Errorf("driveType %s not support", cniConfig.DriverType)
	}

	createEndpointRequest := &pbrpc.CreateEndpointRequest{
		Name:             string(k8sConfig.K8S_POD_NAME),
		Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
		InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
		IfName:           args.IfName,
		NetNs:            args.Netns,
		IpamType:         ipamType,
		IpamArgs:         &pbrpc.IpamArgs{DeviceId: cniConfig.RuntimeConfig.DeviceID},
	}
	createEndpointResponse, err := celloClient.CreateEndpoint(ctx, createEndpointRequest)
	if err != nil {
		return fmt.Errorf("cello create endpoint failed: %v", err)
	}

	defer func() {
		if err != nil {
			deleteEndpointRequest := &pbrpc.DeleteEndpointRequest{
				Name:             string(k8sConfig.K8S_POD_NAME),
				Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
				InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
				IfName:           args.IfName,
				IpamType:         ipamType,
				IpamArgs:         &pbrpc.IpamArgs{DeviceId: cniConfig.RuntimeConfig.DeviceID},
			}
			_, err = celloClient.DeleteEndpoint(ctx, deleteEndpointRequest)
			if err != nil {
				lg.Errorf("Request to delete endpoint failed: %v", err)
			}
		}
	}()

	networkConfig, err := generateSetupConfig(args, cniConfig, createEndpointResponse.GetInterfaces())
	if err != nil {
		return err
	}

	err = driver.SetupDataPath(networkConfig)
	if err != nil {
		return err
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
	lg.Debugf("CNI Result: %s", cniResultJson)

	err = cniTypes.PrintResult(cniResult, cniResult.Version())
	if err != nil {
		return err
	}
	return nil
}

func CmdDel(args *skel.CmdArgs) (err error) {
	_, cniConfig, k8sConfig, err := types.ParseCmdArgs(args)
	if err != nil {
		lg.ErrorS(err, "Parse cmdArgs failed")
		return err
	}
	lg.Infof("CniConf: %+v", cniConfig)

	lg = lg.WithFields(logger.Fields{
		"Namespace":   k8sConfig.K8S_POD_NAMESPACE,
		"NetName":     k8sConfig.K8S_POD_NAME,
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

	err = driver.GenericTeardownNetwork(args.Netns)
	if err != nil {
		lg.ErrorS(err, "Teardown driver failed", "PodNamespace", k8sConfig.K8S_POD_NAMESPACE, "PodName", k8sConfig.K8S_POD_NAME, "IfName", args.IfName)
		return nil
	}
	lg.InfoS("Teardown driver success", "PodNamespace", k8sConfig.K8S_POD_NAMESPACE, "PodName", k8sConfig.K8S_POD_NAME, "IfName", args.IfName)

	var ipamType string
	switch strings.ToLower(cniConfig.DriverType) {
	case strings.ToLower(pbrpc.IfType_TypePhysicsShare.String()):
		ipamType = celloTypes.IPAMTypeRdmaShare
	case strings.ToLower(pbrpc.IfType_TypePhysicsExclusive.String()):
		ipamType = celloTypes.IPAMTypeRdmaExclusive
	default:
		return fmt.Errorf("driveType %s not support", cniConfig.DriverType)
	}

	deleteEndpointRequest := &pbrpc.DeleteEndpointRequest{
		Name:             string(k8sConfig.K8S_POD_NAME),
		Namespace:        string(k8sConfig.K8S_POD_NAMESPACE),
		InfraContainerId: string(k8sConfig.K8S_POD_INFRA_CONTAINER_ID),
		IfName:           args.IfName,
		IpamType:         ipamType,
		IpamArgs:         &pbrpc.IpamArgs{DeviceId: cniConfig.RuntimeConfig.DeviceID}, // deviceId maybe empty
	}
	_, err = celloClient.DeleteEndpoint(ctx, deleteEndpointRequest)
	if err != nil {
		lg.Errorf("Request to delete endpoint failed: %s", err.Error())
		return err
	}
	lg.Infof("Request to delete endpoint succeed")
	return nil
}

func CmdCheck(_ *skel.CmdArgs) error {
	return nil
}

func generateSetupConfig(args *skel.CmdArgs, conf *types.NetConf, networks []*pbrpc.NetworkInterface) (*types.SetupConfig, error) {
	var network *pbrpc.NetworkInterface
	for _, n := range networks {
		if n.IfName == args.IfName {
			network = n
			break
		}
	}
	if network == nil {
		return nil, fmt.Errorf("not found network config for %s", args.IfName)
	}

	masterLink, err := iproute.LinkByMac(network.GetENI().GetMac())
	if err != nil {
		return nil, fmt.Errorf("could not found dev [%s]: %v", network.GetENI().GetMac(), err)
	}

	var (
		podIPv4Net  *net.IPNet
		podIPv6Net  *net.IPNet
		gatewayIPv4 net.IP
		gatewayIPv6 net.IP
	)

	getPodIPSet := func(podIP string) (*net.IPNet, error) {
		ipAddr, n, inErr := net.ParseCIDR(podIP)
		if inErr != nil {
			return nil, inErr
		}
		n.IP = ipAddr
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

	networkConfig := &types.SetupConfig{
		ENIIndex:     masterLink.Attrs().Index,
		IfName:       args.IfName,
		NetNSPath:    args.Netns,
		IPv4:         podIPv4Net,
		IPv4Gateway:  gatewayIPv4,
		IPv6:         podIPv6Net,
		IPv6Gateway:  gatewayIPv6,
		HostLink:     masterLink,
		HostIPSet:    &celloTypes.IPSet{},
		BandWidth:    conf.RuntimeConfig.Bandwidth,
		DefaultRoute: network.DefaultRoute,
		Vid:          network.GetENI().GetVid(),
	}
	var routes []cniTypes.Route
	for _, r := range network.ExtraRoutes {
		ipAddr, n, inErr := net.ParseCIDR(r.Dst)
		if inErr != nil {
			return nil, fmt.Errorf("parse extra routes failed, %w", inErr)
		}
		route := cniTypes.Route{Dst: *n}
		if ipAddr.To4() != nil {
			route.GW = gatewayIPv4
		} else {
			route.GW = gatewayIPv6
		}
		routes = append(routes, route)
	}
	networkConfig.ExtraRoutes = routes

	switch strings.ToLower(conf.DriverType) {
	case strings.ToLower(pbrpc.IfType_TypePhysicsShare.String()):
		networkConfig.DP = types.IPVlan
		networkConfig.ExtraNeigh = []types.Neigh{{
			Dst: ip.NextIP(gatewayIPv4),
			Mac: masterLink.Attrs().HardwareAddr,
		}}
	case strings.ToLower(pbrpc.IfType_TypePhysicsExclusive.String()):
		networkConfig.DP = types.ENI
	default:
		return nil, fmt.Errorf("unsupported ipType %d", network.IfType)
	}

	return networkConfig, nil
}
