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

package violin

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes"

	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/utils/logger"
)

// Daemon is the daemon liteAgent for cello-meta CNI.
type Daemon interface {
	Start(hasStarted chan<- struct{}) error
	Stop()
	pbrpc.CelloServer
}

// liteAgent is a lightweight cello-liteAgent which mainly acts like a kubernetes APIServer proxy.
type liteAgent struct {
	opt *option

	k8s k8s.Service
	mgr *IPManager

	ctx       context.Context
	cancel    context.CancelFunc
	logger    logger.Logger
	rpcServer *grpc.Server
	pbrpc.UnimplementedCelloServer
}

// option records options for cello-lite liteAgent.
type option struct {
	nodeName       string
	k8sClientQPS   float64
	k8sClientBurst int
	k8sContentType string
	useragent      string
	apiAddress     string
	k8sClient      kubernetes.Interface
	networks       *NetworkConfig
}

// LiteAgentOption sets options API address and useragent for cello-lite liteAgent.
type LiteAgentOption func(*option)

// WithK8sQPS returns a LiteAgentOption which sets liteAgent's k8s client request QPS.
func WithK8sQPS(qps float64) LiteAgentOption {
	return func(opt *option) {
		opt.k8sClientQPS = qps
	}
}

// WithK8sBurst returns a LiteAgentOption which sets liteAgent's k8s client requests burst.
func WithK8sBurst(burst int) LiteAgentOption {
	return func(opt *option) {
		opt.k8sClientBurst = burst
	}
}

// WithK8sContentType returns a LiteAgentOption which sets liteAgent's content type in k8s requests' header.
func WithK8sContentType(contentType string) LiteAgentOption {
	return func(opt *option) {
		opt.k8sContentType = contentType
	}
}

// WithUserAgent returns a LiteAgentOption which sets request's user-liteAgent for k8s.
func WithUserAgent(userAgent string) LiteAgentOption {
	return func(opt *option) {
		opt.useragent = userAgent
	}
}

// WithAgentAPIAddress returns a LiteAgentOption which sets rpc endpoints path.
func WithAgentAPIAddress(addr string) LiteAgentOption {
	return func(opt *option) {
		opt.apiAddress = addr
	}
}

// WithKubeClient returns a LiteAgentOption which sets agent use given k8s client.
func WithKubeClient(client kubernetes.Interface) LiteAgentOption {
	return func(opt *option) {
		opt.k8sClient = client
	}
}

// WithIPManager returns a LiteAgentOption which sets agent
func WithIPManager(config *NetworkConfig) LiteAgentOption {
	return func(opt *option) {
		opt.networks = config
	}
}

// NewDaemonWithOptions returns a cello-lite liteAgent.
func NewDaemonWithOptions(ctx context.Context, nodeName string, options ...LiteAgentOption) (Daemon, error) {
	opt := option{
		nodeName:       nodeName,
		k8sClientQPS:   DefaultKubeClientQPS,
		k8sClientBurst: DefaultKubeClientBurst,
		k8sContentType: DefaultKubeContentType,
		useragent:      DefaultUserAgent,
		apiAddress:     DefaultRPCAddress,
	}

	for _, optionFunc := range options {
		optionFunc(&opt)
	}

	var err error
	log := logger.GetLogger().WithFields(logger.Fields{"subsys": "cello-lite-agent"})

	if opt.k8sClient == nil {
		opt.k8sClient, err = k8s.NewInClusterK8sClient(&opt.k8sClientQPS, &opt.k8sClientBurst, &opt.k8sContentType, opt.useragent)
		if err != nil {
			return nil, fmt.Errorf("failed to create k8sService clientset: %w", err)
		}
	}

	k8sService, err := k8s.NewK8sService(opt.nodeName, opt.k8sClient)
	if err != nil {
		return nil, fmt.Errorf("faild to create k8sService service manager: %w", err)
	}

	var ipam *IPManager
	if opt.networks != nil {
		ipam, err = NewIPManager(opt.networks)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPManager %v", err)
		} else {
			log.Info("Found devices:")
			for _, dev := range ipam.ListDevices() {
				log.InfoS("device", "name", dev.IfName(), "id", dev.PciId())
			}
		}
	}

	return NewDaemon(ctx, k8sService, ipam, &opt, log), nil
}

func NewDaemon(ctx context.Context, service k8s.Service, ipam *IPManager, opt *option, parentLogger logger.Logger) Daemon {
	agentContext, cancel := context.WithCancel(ctx)
	return &liteAgent{
		logger:                   parentLogger,
		opt:                      opt,
		ctx:                      agentContext,
		cancel:                   cancel,
		k8s:                      service,
		mgr:                      ipam,
		UnimplementedCelloServer: pbrpc.UnimplementedCelloServer{},
	}
}

func (agent *liteAgent) startRPCService(ctx context.Context) error {
	listener, err := net.Listen("unix", agent.opt.apiAddress)
	if err != nil {
		return fmt.Errorf("rpc service: failed to listent on %v due to： %w", agent.opt.apiAddress, err)
	}
	if agent.rpcServer != nil {
		agent.rpcServer.Stop()
		agent.rpcServer = nil
	}

	agent.rpcServer = grpc.NewServer()
	pbrpc.RegisterCelloServer(agent.rpcServer, agent)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				agent.logger.InfoS("Start grpc server", "address", agent.opt.apiAddress)
				err = agent.rpcServer.Serve(listener)
				if err == nil {
					agent.logger.Info("GRPC server stopped")
					return
				}
				agent.logger.ErrorS(err, "GRPC server unexpected stopped, restarting")
				time.Sleep(time.Second * 5)
			}
		}
	}()

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dailUnix(timeoutCtx, agent.opt.apiAddress)
	if err != nil {
		return fmt.Errorf("failed to connect to liteAgent %w", err)
	}
	err = conn.Close()
	if err != nil {
		return err
	}

	return nil
}

func (agent *liteAgent) Start(hasStarted chan<- struct{}) error {
	err := agent.startRPCService(agent.ctx)
	if err != nil {
		return fmt.Errorf("daemon: failed to start rpc servive %w", err)
	}
	agent.logger.Info("Daemon is running")
	close(hasStarted)
	<-agent.ctx.Done()
	return nil
}

func (agent *liteAgent) Stop() {
	agent.cancel()
	if agent.rpcServer != nil {
		agent.rpcServer.Stop()
	}
	agent.logger.Info("Daemon stopped")
}

// GetPodMetaInfo returns Pod metadata.
func (agent *liteAgent) GetPodMetaInfo(ctx context.Context, request *pbrpc.GetPodMetaRequest) (*pbrpc.GetPodMetaResponse, error) {
	pod, err := agent.k8s.GetCachedPod(request.GetNamespace(), request.GetName())
	if err != nil {
		return nil, err
	}
	if pod == nil {
		return nil, fmt.Errorf("no found pod, namespace:%s, name:%s", request.GetNamespace(), request.GetName())
	}
	response := &pbrpc.GetPodMetaResponse{
		Annotations: pod.Annotations,
	}
	return response, nil
}

// PatchPodAnnotation patches pod annotation.
func (agent *liteAgent) PatchPodAnnotation(ctx context.Context, request *pbrpc.PatchPodAnnotationRequest) (*pbrpc.PatchPodAnnotationResponse, error) {
	return &pbrpc.PatchPodAnnotationResponse{}, agent.k8s.PatchPodAnnotation(ctx, request.GetNamespace(),
		request.GetName(), request.GetAnnotations())
}

func dailUnix(ctx context.Context, path string) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, path,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", path, time.Second*10)
		}),
	)
	return conn, err
}

func (agent *liteAgent) CreateEndpoint(_ context.Context, req *pbrpc.CreateEndpointRequest) (resp *pbrpc.CreateEndpointResponse, err error) {
	ctxLogger := agent.logger.WithFields(
		logger.Fields{
			"Namespace":          req.Namespace,
			"Name":               req.Name,
			"SandboxContainerId": req.InfraContainerId,
			"IfName":             req.IfName,
			"IpamType":           req.IpamType,
			"IpamArgs":           req.IpamArgs.String(),
			"TraceID":            uuid.New(),
		},
	)
	ctxLogger.Info("Handle CreateEndpoint")

	defer func() {
		if err != nil {
			ctxLogger.ErrorS(err, "Fail to handle CreateEndpoint")
		} else {
			ctxLogger.InfoS("CreateEndpoint success: ", "result", resp.String())
		}
	}()

	if agent.mgr == nil {
		return nil, fmt.Errorf("network manager not initialized")
	}

	var netWorkInterface *pbrpc.NetworkInterface
	deviceId := req.GetIpamArgs().GetDeviceId()
	dev, exist := agent.mgr.DeviceById(deviceId)
	if !exist {
		err = fmt.Errorf("can't find device by identity %s", deviceId)
		return nil, err
	}
	ipCfg, err := agent.mgr.ipams.Get(dev.IfName(), req.InfraContainerId, req.IfName, nil)
	if err != nil {
		return nil, err
	}
	var v4Addr, v4Gw, v6Addr, v6Gw string
	if ipCfg.Address.IP.To4() != nil {
		v4Addr = ipCfg.Address.String()
		//v4Gw = ipCfg.Gateway.String()
	} else {
		v6Addr = ipCfg.Address.String()
		//v6Gw = ipCfg.Gateway.String()
	}

	netWorkInterface = &pbrpc.NetworkInterface{
		ENI: &pbrpc.ENI{
			Mac:         dev.HwAddr(),
			IPv4Gateway: v4Gw,
			IPv6Gateway: v6Gw,
			Trunk:       false,
		},
		IPv4Addr:     v4Addr,
		IPv6Addr:     v6Addr,
		IfName:       req.IfName,
		DefaultRoute: false,
		IfType:       0,
	}
	_, network, err := net.ParseCIDR(ipCfg.Address.String())
	if err != nil {
		return nil, err
	}
	netWorkInterface.ExtraRoutes = []*pbrpc.Route{{Dst: network.String()}}
	return &pbrpc.CreateEndpointResponse{Interfaces: []*pbrpc.NetworkInterface{netWorkInterface}}, nil
}

func (agent *liteAgent) DeleteEndpoint(_ context.Context, req *pbrpc.DeleteEndpointRequest) (resp *pbrpc.DeleteEndpointResponse, err error) {
	ctxLogger := agent.logger.WithFields(
		logger.Fields{
			"Namespace":          req.Namespace,
			"Name":               req.Name,
			"SandboxContainerId": req.InfraContainerId,
			"IfName":             req.IfName,
			"IpamType":           req.IpamType,
			"IpamArgs":           req.IpamArgs.String(),
			"TraceID":            uuid.New().String(),
		},
	)
	ctxLogger.Info("Handle DeleteEndpoint")

	defer func() {
		if err != nil {
			ctxLogger.ErrorS(err, "Fail to handle CreateEndpoint")
		} else {
			ctxLogger.Info("DeleteEndpoint success: ", "result", resp.String())
		}
	}()

	if agent.mgr == nil {
		return nil, fmt.Errorf("network manager not initialized")
	}

	dev, exist := agent.mgr.DeviceById(req.GetIpamArgs().GetDeviceId())
	if !exist {
		err = agent.mgr.ipams.Release("", req.InfraContainerId, req.IfName)
		if err != nil {
			return nil, err
		}
	} else {
		err = agent.mgr.ipams.Release(dev.IfName(), req.InfraContainerId, req.IfName)
		if err != nil {
			return nil, err
		}
	}
	return &pbrpc.DeleteEndpointResponse{}, nil
}
