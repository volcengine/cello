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

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	k8sErr "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/volcengine/cello/pkg/backoff"
	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/deviceplugin"
	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/pool"
	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/credential"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
	"github.com/volcengine/cello/pkg/signal"
	"github.com/volcengine/cello/pkg/store"
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/utils/math"
	"github.com/volcengine/cello/pkg/utils/netns"
	"github.com/volcengine/cello/pkg/utils/runtime"
	"github.com/volcengine/cello/pkg/version"
	"github.com/volcengine/cello/types"
)

const (
	envNodeName        = "NODE_NAME"
	DefaultSocketPath  = "/var/run/cello/cni.socket"
	podPersistencePath = "/var/run/cello/Resource.db"
	celloConfigMapPath = "/etc/cello/cello-config"
	HpcInfoPath        = "/var/run/cello/hpcInstancePosition"
)

// daemon is the cello daemon that is in charge of manage the resources consumed by kubernetes network.
type daemon struct {
	networkMode      string
	apiListenAddress string
	pendingPods      sync.Map

	instanceMeta          helper.InstanceMetadataGetter
	instanceLimit         helper.InstanceLimitManager
	ecsMetaGetter         ec2.APIGroupECS
	k8s                   k8s.Service
	podPersistenceManager PodPersistenceManager
	subnetManager         helper.SubnetManager
	securityGroupManager  helper.SecurityGroupManager
	eniManager            *eniResourceManager
	eniIPManager          *eniIPResourceManager
	managers              map[string]ResourceManager // NetResourceType - ResourceManager
	devicePluginManager   deviceplugin.Manager
	lastGC                time.Time
	pbrpc.UnimplementedCelloServer

	rdmaIpamManager *RdmaIpamManager
}

// createEc2 creates an ec2 client.
func createEc2(instanceMeta helper.InstanceMetadataGetter) (ec2.EC2, error) {
	var credentialProvider credential.Provider
	if config.Config.RamRole != nil {
		log.InfoS("Set credential provider by ramRole", "RamRole", *config.Config.RamRole)
		credentialProvider = credential.NewSTSProvider(*config.Config.RamRole)
	} else if config.Config.CredentialAccessKeyId != nil && config.Config.CredentialAccessKeySecret != nil {
		log.InfoS("Set credential provider by static ak/sk")
		credentialProvider = credential.NewStaticProvider(&credential.Credential{
			AccessKeyId:     datatype.StringValue(config.Config.CredentialAccessKeyId),
			SecretAccessKey: datatype.StringValue(config.Config.CredentialAccessKeySecret),
		})
	} else {
		return nil, fmt.Errorf("no credential provided")
	}

	endpoint := ""
	if config.Config.OpenApiAddress != nil {
		log.InfoS("Set openapi address", "OpenApiAddress", *config.Config.OpenApiAddress)
		endpoint = *config.Config.OpenApiAddress
	}
	apiClient := ec2.NewClient(instanceMeta.GetRegion(), endpoint, credentialProvider)
	return apiClient, nil
}

func NewDaemon() (*daemon, error) {
	// k8s
	nodeName := os.Getenv(envNodeName)
	if nodeName == "" {
		return nil, fmt.Errorf("get env %s failed", envNodeName)
	}
	version.NodeName = nodeName

	// mounted json config
	staticCfg, err := config.ParseStaticConfig(celloConfigMapPath)
	if err != nil {
		return nil, fmt.Errorf("parse static json config failed: %v", err)
	}

	k8sClientSet, err := k8s.NewInClusterK8sClient(staticCfg.KubeClientQPS, staticCfg.KubeClientBurst,
		staticCfg.KubeContentType, version.UserAgent())
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset failed: %v", err)
	}

	k8sService, err := k8s.NewK8sService(nodeName, k8sClientSet)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes service failed: %v", err)
	}

	// cfg
	err = config.ParseConfig(k8sService)
	if err != nil {
		return nil, fmt.Errorf("parse config failed, %v", err)
	}

	// instanceMetaGetter
	instanceMeta := helper.GetInstanceMetadata()

	// resource db
	podPersist, err := newPodPersistenceManager(podPersistencePath, "pod")
	if err != nil {
		return nil, fmt.Errorf("create persistence db failed: %w", err)
	}

	apiClient, err := createEc2(instanceMeta)
	if err != nil {
		return nil, err
	}

	if config.Config.ProjectName == nil {
		projectName, inErr := getInstanceProject(apiClient, instanceMeta)
		if inErr != nil {
			return nil, fmt.Errorf("get instance projectName failed, %v", inErr)
		}
		log.Infof("Use the instance project %s as the project of eni", projectName)
		config.Config.ProjectName = datatype.String(projectName)
	}

	return newDaemon(k8sService, apiClient, podPersist, instanceMeta, nil)
}

func newDaemon(k8sService k8s.Service, apiClient ec2.EC2, podPersist PodPersistenceManager,
	instanceMeta helper.InstanceMetadataGetter, volcApi helper.VolcAPI) (*daemon, error) {
	// register metrics
	metrics.PrometheusRegister()

	// register global event recorder
	tracing.RegisterEventRecorder(k8sService.RecordNodeEvent, k8sService.RecordPodEvent)

	subnetManager, err := helper.NewPodSubnetManager(instanceMeta.GetAvailabilityZone(), instanceMeta.GetVpcId(), apiClient,
		helper.WithEventRecord(tracing.DefaultGlobalTracer()), helper.WithDefaultEventLimiter())
	if err != nil {
		return nil, fmt.Errorf("create pod subnets manager failed, %w", err)
	}

	secGrpManager := helper.NewSecurityGroupManager()

	err = subnetManager.FlushSubnets(config.Config.Subnets...)
	if err != nil {
		return nil, fmt.Errorf("set subnets failed, %v", err)
	}

	err = secGrpManager.UpdateSecurityGroups(config.Config.SecurityGroups)
	if err != nil {
		return nil, fmt.Errorf("set securityGroups failed, %v", err)
	}

	if volcApi == nil {
		volcApi, err = helper.New(apiClient, types.IPFamily(*config.Config.IPFamily), subnetManager, instanceMeta,
			datatype.StringValue(config.Config.Platform),
			datatype.StringValue(config.Config.AccountSitePrefix))
		if err != nil {
			return nil, err
		}
	}

	d := &daemon{
		networkMode:              *config.Config.NetworkMode,
		apiListenAddress:         DefaultSocketPath,
		pendingPods:              sync.Map{},
		k8s:                      k8sService,
		instanceMeta:             instanceMeta,
		ecsMetaGetter:            apiClient,
		podPersistenceManager:    podPersist,
		subnetManager:            subnetManager,
		securityGroupManager:     secGrpManager,
		managers:                 map[string]ResourceManager{},
		UnimplementedCelloServer: pbrpc.UnimplementedCelloServer{},
	}
	d.instanceLimit, err = helper.NewInstanceLimitManager(volcApi)
	if err != nil {
		return nil, err
	}

	err = d.syncPodPersistence()
	if err != nil {
		return nil, fmt.Errorf("sync pod persistence failed while daemon init, %v", err)
	}
	oldPods, err := podPersist.List()
	if err != nil {
		return nil, fmt.Errorf("list pod from persistence failed, %v", err)
	}
	allocatedResMap := types.GetNetResourceAllocatedFromPods(oldPods)

	switch d.networkMode {
	case config.NetworkModeENIExclusive:
		d.eniManager, err = newEniResourceManager(subnetManager, secGrpManager,
			volcApi, allocatedResMap[types.NetResourceTypeEni], k8sService)
		if err != nil {
			return nil, fmt.Errorf("create eni resource manager failed, %v", err)
		}
		d.managers[types.NetResourceTypeEni] = d.eniManager
		d.devicePluginManager = deviceplugin.NewResourcePluginManager(context.TODO(),
			deviceplugin.NewENIDevicePlugin(deviceplugin.ENIResourceName,
				math.Max(0, d.eniManager.GetResourceLimit()-d.GetStockPodCount())))
		if d.eniManager.SupportTrunk() {
			d.devicePluginManager.AddPlugin(deviceplugin.NewENIDevicePlugin(
				deviceplugin.BranchENIResourceName,
				d.eniManager.GetTrunkBranchLimit()))
		}
		sigChannel := make(chan struct{}, 1)
		d.instanceLimit.WatchUpdate("device-plugin-eni", sigChannel)
		go watchResourceNum(context.TODO(), d.devicePluginManager, deviceplugin.ENIResourceName, func() int {
			return math.Max(0, d.eniManager.GetResourceLimit()-d.GetStockPodCount())
		}, sigChannel)

	case config.NetworkModeENIShare:
		d.eniIPManager, err = newEniIPResourceManager(subnetManager, secGrpManager,
			volcApi, allocatedResMap[types.NetResourceTypeEniIp], k8sService)
		if err != nil {
			return nil, fmt.Errorf("create eniIP resource manager failed, %v", err)
		}
		d.managers[types.NetResourceTypeEniIp] = d.eniIPManager
		d.devicePluginManager = deviceplugin.NewResourcePluginManager(context.TODO(),
			deviceplugin.NewENIDevicePlugin(deviceplugin.ENIIPResourceName,
				math.Max(0, d.eniIPManager.GetResourceLimit()-d.GetStockPodCount())))
		if d.eniIPManager.SupportTrunk() {
			d.devicePluginManager.AddPlugin(deviceplugin.NewENIDevicePlugin(
				deviceplugin.BranchENIResourceName,
				d.eniIPManager.GetTrunkBranchLimit()))
		}
		sigChannel := make(chan struct{}, 1)
		d.instanceLimit.WatchUpdate("device-plugin-eniip", sigChannel)
		go watchResourceNum(context.TODO(), d.devicePluginManager, deviceplugin.ENIIPResourceName, func() int {
			return math.Max(0, d.eniIPManager.GetResourceLimit()-d.GetStockPodCount())
		}, sigChannel)
	default:
		return nil, fmt.Errorf("no support network mode %s", d.networkMode)
	}

	if datatype.StringValue(config.Config.Source) == config.SourceClusterConfigMap {
		d.k8s.AddConfigMapEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(_, newObj interface{}) {
				newConfig, err := config.GetCelloConfigFromConfigMap(newObj)
				if err != nil {
					_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventConfigMapUpdateFailed, err.Error())
					log.ErrorS(err, "Get cello config failed while configmap update")
					return
				}
				if !sets.NewString(config.Config.Subnets...).Equal(sets.NewString(newConfig.Subnets...)) {
					err = d.subnetManager.FlushSubnets(newConfig.Subnets...)
					if err != nil {
						_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventUpdateSubnetFailed, err.Error())
						log.ErrorS(err, "Update subnet list failed")
						return
					}
					config.Config.Subnets = newConfig.Subnets
				}

				if !sets.NewString(config.Config.SecurityGroups...).Equal(sets.NewString(newConfig.SecurityGroups...)) {
					err = d.securityGroupManager.UpdateSecurityGroups(newConfig.SecurityGroups)
					if err != nil {
						_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventUpdateSecurityGroupFailed, err.Error())
						log.ErrorS(err, "Update security group list failed")
						return
					}
					config.Config.SecurityGroups = newConfig.SecurityGroups
				}

				if datatype.Uint32Value(newConfig.PoolTarget) != datatype.Uint32Value(config.Config.PoolTarget) ||
					datatype.Uint32Value(newConfig.PoolTargetMin) != datatype.Uint32Value(config.Config.PoolTargetMin) {
					if d.eniManager != nil {
						d.eniManager.pool.ReCfgCache(int(datatype.Uint32Value(newConfig.PoolTarget)), int(datatype.Uint32Value(newConfig.PoolTargetMin)))
						config.Config.PoolTarget = newConfig.PoolTarget
						config.Config.PoolTargetMin = newConfig.PoolTargetMin
					}
					if d.eniIPManager != nil {
						d.eniIPManager.pool.ReCfgCache(int(datatype.Uint32Value(newConfig.PoolTarget)), int(datatype.Uint32Value(newConfig.PoolTargetMin)))
						config.Config.PoolTarget = newConfig.PoolTarget
						config.Config.PoolTargetMin = newConfig.PoolTargetMin
					}
				}
			},
		})
	}

	if datatype.BoolValue(config.Config.EnableRdmaIpam) && d.instanceLimit.GetLimit().RdmaSupport {
		err = d.initRdmaIpamManager()
		if err != nil {
			log.ErrorS(err, "Init rdma ipam failed")
		}
		go wait.PollUntilContextCancel(context.TODO(), 3*time.Hour, true, func(ctx context.Context) (bool, error) {
			return updateHpcTopologyInfo(d.k8s, apiClient, instanceMeta)
		})
	}

	return d, nil
}

func updateHpcTopologyInfo(k8sService k8s.Service, apiClient ec2.EC2, instanceMeta helper.InstanceMetadataGetter) (bool, error) {
	// Describe Hpc Instance Position
	hpcInstPosInfo := &ec2.HpcInstancePositionInfoForDescribeHpcInstancePositionOutput{}
	// read hpcInstancePosition from hpc info file
	if content, err := os.ReadFile(HpcInfoPath); err != nil {
		log.ErrorS(err, "Read hpc instance position info file failed")
	} else {
		err = json.Unmarshal(content, hpcInstPosInfo)
		if err != nil {
			log.ErrorS(err, "Unmarshal hpcInstPosInfo failed")
		} else {
			log.InfoS("Unmarshal hpcInstPosInfo success", "InstanceId", volcengine.StringValue(hpcInstPosInfo.InstanceId),
				"SwitchName", volcengine.StringValue(hpcInstPosInfo.SwitchName), "RdmaMinipod", volcengine.StringValue(hpcInstPosInfo.RdmaMinipod))
		}
	}

	log.InfoS("Start update hpc instance position info")
	// call open api get hpc instance position
	if hpcInstPosInfo.SwitchName == nil {
		log.InfoS("Call DescribeHpcInstancePosition api to get hpc info")
		out, err := apiClient.DescribeHpcInstancePosition(&ec2.DescribeHpcInstancePositionInput{InstanceId: volcengine.String(instanceMeta.GetInstanceId())})
		if err != nil {
			log.ErrorS(err, "DescribeHpcInstancePosition failed")
			return false, nil
		}
		if len(out.HpcInstancePositionInfos) != 1 || out.HpcInstancePositionInfos[0] == nil || out.HpcInstancePositionInfos[0].SwitchName == nil {
			log.ErrorS(fmt.Errorf("empty resp"), "DescribeHpcInstancePosition failed", "HpcInstancePositionInfos", out.HpcInstancePositionInfos)
			return false, nil
		}
		hpcInstPosInfo = out.HpcInstancePositionInfos[0]
		log.InfoS("DescribeHpcInstancePosition success", "InstanceId", volcengine.StringValue(hpcInstPosInfo.InstanceId),
			"SwitchName", volcengine.StringValue(hpcInstPosInfo.SwitchName), "RdmaMinipod", volcengine.StringValue(hpcInstPosInfo.RdmaMinipod))
		// cache hpc info to file
		if b, mErr := json.Marshal(hpcInstPosInfo); mErr == nil {
			if err = os.WriteFile(HpcInfoPath, b, 0644); err != nil {
				log.ErrorS(err, "Store hpcInstPosInfo to file failed", "HpcInfoPath", HpcInfoPath)
			}
		} else {
			// should never get into here
			// if Marshal() failed, cello won't WriteFile unless cello restart
			log.ErrorS(err, "Marshal hpcInstPosInfo failed")
		}
	}

	node, err := k8sService.GetLocalNode(context.TODO())
	if err != nil {
		log.ErrorS(err, "GetLocalNode failed")
		return false, nil
	}
	hpcInstPos, _ := node.GetLabels()[types.LabelHpcInstanceSwitchPosition]
	if hpcInstPos != "" && hpcInstPos == volcengine.StringValue(hpcInstPosInfo.SwitchName) {
		log.InfoS("Skip patch node hpc switch label, node hpc instance position label matching cache",
			"label", map[string]string{types.LabelHpcInstanceSwitchPosition: hpcInstPos})
		return true, nil
	}

	// patch label to Node
	m := map[string]string{types.LabelHpcInstanceSwitchPosition: volcengine.StringValue(hpcInstPosInfo.SwitchName)}
	if err = k8sService.PatchNodeLabels(m); err != nil {
		log.ErrorS(err, "Patch hpc instance switch position label failed", "label", m)
		return false, nil
	}
	log.InfoS("Patch hpc instance switch position label success", "label", m)
	return true, nil
}

func (d *daemon) gc() error {
	if time.Since(d.lastGC) < time.Minute {
		return nil
	}
	signal.MuteChannel(signal.WakeGC)
	defer signal.UnmuteChannel(signal.WakeGC)
	var err error

	log.Infof("Daemon GC start")
	defer func() {
		if err != nil {
			log.ErrorS(err, "Daemon gc failed")
		} else {
			d.lastGC = time.Now()
			log.Infof("Daemon GC finished")
		}
	}()

	getAllocatedResMap := func(resType string) func() (map[string]types.NetResourceAllocated, error) {
		return func() (map[string]types.NetResourceAllocated, error) {
			if inErr := d.syncPodPersistence(); inErr != nil {
				return nil, fmt.Errorf("sync pod persistence failed, %v", inErr)
			}
			oldPods, inErr := d.podPersistenceManager.List()
			if inErr != nil {
				return nil, fmt.Errorf("list pod from persistence failed, %v", inErr)
			}
			allocatedResMap := types.GetNetResourceAllocatedFromPods(oldPods)
			return allocatedResMap[resType], nil
		}
	}

	var eniGCErr error
	if d.eniManager != nil {
		if eniGCErr = d.eniManager.pool.GC(getAllocatedResMap(types.NetResourceTypeEni)); eniGCErr != nil {
			eniGCErr = fmt.Errorf("pool of eni gc failed, %v", eniGCErr)
		}
	}

	var ipGCErr error
	if d.eniIPManager != nil {
		if ipGCErr = d.eniIPManager.pool.GC(getAllocatedResMap(types.NetResourceTypeEniIp)); ipGCErr != nil {
			ipGCErr = fmt.Errorf("pool of eni-ip gc failed, %v", ipGCErr)
		}
	}
	err = k8sErr.NewAggregate([]error{eniGCErr, ipGCErr})
	return err
}

func (d *daemon) start(stopCh chan struct{}) error {
	period := time.Duration(*config.Config.ReconcileIntervalSec) * time.Second
	once := sync.Once{}
	sig := make(chan signal.SigData)
	err := signal.RegisterChannel(signal.WakeGC, sig)
	if err != nil {
		return err
	}
	defer func() {
		signal.MuteChannel(signal.WakeGC)
		close(sig)
	}()
	go wait.JitterUntil(func() {
		once.Do(func() {
			time.Sleep(period)
		})
		if gcErr := d.gc(); gcErr != nil {
			log.Error("gc err:", gcErr)
		}

	}, period, 0.2, true, stopCh)

	go func() {
		for {
			select {
			case <-stopCh:
				return
			case <-sig:
				if gcErr := d.gc(); gcErr != nil {
					log.Error("gc err:", gcErr)
				}
			}
		}
	}()

	// block
	if err = d.startServers(stopCh); err != nil {
		return err
	}
	return nil
}

func (d *daemon) judgmentEvictPod(ctx *netContext, resourceLimit int) error {
	pods, err := d.podPersistenceManager.List()
	if err == nil && len(pods) >= resourceLimit {
		info := "number of pods currently exceeds available net resources"
		ctx.log.InfoS("Pod evicted", "info", info)
		if err = d.k8s.EvictPod(ctx, ctx.pod.Name, ctx.pod.Namespace); err != nil {
			ctx.log.ErrorS(err, "Pod evicted failed")
			return fmt.Errorf("%s, pod evicted but failed, %v", info, err)
		} else {
			return fmt.Errorf("%s, pod evicted", info)
		}
	}
	return nil
}

// allocateENI allocates ENI for pod.
func (d *daemon) allocateENI(ctx *netContext, oldPod *types.Pod) (*types.ENI, error) {
	oldRes := oldPod.GetVPCResourceByType(types.NetResourceTypeEni)
	prefer := ""
	if length := len(oldRes); length > 1 {
		ctx.Log().WarnS("ENI for pod is more than one", "pod", types.PodKey(oldPod.Namespace, oldPod.Name))
	} else if length == 1 {
		prefer = oldRes[0].ID
	}

	if prefer == "" && ctx.pod.AllowEviction {
		err := d.judgmentEvictPod(ctx, d.eniManager.GetResourceLimit())
		if err != nil {
			return nil, err
		}
	}

	eni, err := d.eniManager.Allocate(ctx, prefer)
	if err != nil {
		return nil, err
	}
	return eni.(*types.ENI), nil
}

// allocateENIIP allocates ENI IP for pod.
func (d *daemon) allocateENIIP(ctx *netContext, oldPod *types.Pod) (*types.ENIIP, error) {
	oldRes := oldPod.GetVPCResourceByType(types.NetResourceTypeEniIp)
	prefer := ""
	if length := len(oldRes); length > 1 {
		ctx.Log().WarnS("ENI for pod is more than one", "pod", types.PodKey(oldPod.Namespace, oldPod.Name))
	} else if length == 1 {
		prefer = oldRes[0].ID
	}

	if prefer == "" && ctx.pod.AllowEviction {
		err := d.judgmentEvictPod(ctx, d.eniIPManager.GetResourceLimit())
		if err != nil {
			return nil, err
		}
	}

	eniip, err := d.eniIPManager.Allocate(ctx, prefer)
	if err != nil {
		return nil, err
	}
	return eniip.(*types.ENIIP), err
}

func (d *daemon) CreateEndpoint(ctx context.Context, req *pbrpc.CreateEndpointRequest) (resp *pbrpc.CreateEndpointResponse, err error) {
	switch req.GetIpamType() {
	case types.IPAMTypeRdmaShare, types.IPAMTypeRdmaExclusive:
		return d.createRdmaEndpoint(ctx, req)
	default:
		return d.createVpcEndpoint(ctx, req)
	}
}

func (d *daemon) DeleteEndpoint(ctx context.Context, req *pbrpc.DeleteEndpointRequest) (resp *pbrpc.DeleteEndpointResponse, err error) {
	switch req.GetIpamType() {
	case types.IPAMTypeRdmaShare, types.IPAMTypeRdmaExclusive:
		return d.deleteRdmaEndpoint(ctx, req)
	default:
		return d.deleteVpcEndpoint(ctx, req)
	}
}

// createVpcEndpoint allocate vpc network resources(ENI, IP) for a pod.
func (d *daemon) createVpcEndpoint(ctx context.Context, req *pbrpc.CreateEndpointRequest) (resp *pbrpc.CreateEndpointResponse, err error) {
	lg := log.WithFields(logger.Fields{
		"Namespace":          req.Namespace,
		"Name":               req.Name,
		"SandboxContainerId": req.InfraContainerId,
		"IfName":             req.IfName,
	})
	lg.InfoS("Handle CreateEndpoint")

	defer runtime.HandleCrash(lg)
	defer func() {
		if err != nil {
			lg.ErrorS(err, "Fail to handle CreateEndpoint")
		} else {
			lg.InfoS("CreateEndpoint", "result", resp.String())
		}
	}()

	_, exist := d.pendingPods.LoadOrStore(types.PodKey(req.Namespace, req.Name), struct{}{})
	if exist {
		return nil, fmt.Errorf("pod %s request processing", types.PodKey(req.Namespace, req.Name))
	}
	defer func() {
		d.pendingPods.Delete(types.PodKey(req.Namespace, req.Name))
	}()

	start := time.Now()
	defer func() {
		metrics.RpcLatency.WithLabelValues("CreateEndpoint", fmt.Sprint(err != nil)).Observe(metrics.MsSince(start))
	}()

	k8sPod, err := d.k8s.GetCachedPod(req.Namespace, req.Name)
	if err != nil {
		return nil, fmt.Errorf("get pod from cache failed, %v", err)
	}

	newPod := d.translatePod(k8sPod)
	newPod.SandboxContainerId = req.InfraContainerId
	newPod.NetNs = req.NetNs
	netCtx := &netContext{
		Context: ctx,
		log:     lg,
		pod:     newPod,
	}

	if !d.verifyPodNetwork(newPod.PodNetworkMode) {
		return nil, fmt.Errorf("pod network mode not match with daemon")
	}

	oldPod, err := d.podPersistenceManager.Get(req.Namespace, req.Name)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		} else {
			oldPod = &types.Pod{}
		}
	}

	defer func() {
		// rollback
		if err != nil {
			for i, r := range netCtx.res {
				err = d.podPersistenceManager.Delete(newPod.Namespace, newPod.Name)
				if err != nil {
					log.ErrorS(err, "Delete pod from db failed while rollback")
				}
				mgr := d.managers[r.Type]
				if mgr == nil {
					lg.WarnS("Find resource without manger", "type", r.Type)
					continue
				}
				err = mgr.Release(netCtx, &netCtx.res[i])
				if err != nil {
					lg.Error("Release resource %s[Type: %s] failed while rollback, %v", r.ID, r.Type, err)
				}
			}
		}
	}()

	var networks []*pbrpc.NetworkInterface
	crdNetworks, err := d.networkFromCRD(newPod)
	if err != nil {
		return nil, err
	}
	networks = append(networks, crdNetworks...)
	mainSet := false
	for _, network := range networks {
		if IsMain(network.GetIfName()) {
			mainSet = true
			break
		}
	}

	if !mainSet {
		switch d.networkMode {
		case config.NetworkModeENIExclusive:
			eni, err := d.allocateENI(netCtx, oldPod)
			if err != nil {
				return nil, fmt.Errorf("allocate resource failed: %v", err)
			}
			eniRes := eni.GetVPCResource()
			newPod.PodNetworkMode = types.PodNetworkModeENIExclusive
			newPod.Resources = append(newPod.Resources, eniRes)
			netCtx.res = append(netCtx.res, eniRes)
			ipSet := eni.PrimaryIP.ToPbWithMask(eni.Subnet.CIDR)
			iFace := &pbrpc.NetworkInterface{
				ENI:          eni.ToPb(),
				IPv4Addr:     ipSet.IPv4,
				IPv6Addr:     ipSet.IPv6,
				IfName:       req.IfName,
				DefaultRoute: true,
				IfType:       pbrpc.IfType_TypeENIExclusive,
			}
			newPod.MainInterface = iFace
			newPod.IsMainInterfaceSharedMode = false
			newPod.CreateTime = time.Now()
			err = d.podPersistenceManager.Put(newPod)
			if err != nil {
				return nil, fmt.Errorf("put pod into store failed, %v", err)
			}
			networks = append(networks, iFace)
		case config.NetworkModeENIShare:
			eniip, err := d.allocateENIIP(netCtx, oldPod)
			if err != nil {
				return nil, fmt.Errorf("allocate resource failed: %v", err)
			}
			ipRes := eniip.GetVPCResource()
			newPod.PodNetworkMode = types.PodNetworkModeENIShare
			newPod.Resources = append(newPod.Resources, ipRes)
			netCtx.res = append(netCtx.res, ipRes)
			ipSet := eniip.IPSet.ToPbWithMask(eniip.ENI.Subnet.CIDR)
			iFace := &pbrpc.NetworkInterface{
				ENI:          eniip.ENI.ToPb(),
				IPv4Addr:     ipSet.IPv4,
				IPv6Addr:     ipSet.IPv6,
				IfName:       req.IfName,
				DefaultRoute: true,
				IfType:       pbrpc.IfType_TypeENIShare,
			}
			newPod.MainInterface = iFace
			newPod.IsMainInterfaceSharedMode = true
			newPod.CreateTime = time.Now()
			err = d.podPersistenceManager.Put(newPod)
			if err != nil {
				return nil, fmt.Errorf("put pod into store failed, %v", err)
			}
			networks = append(networks, iFace)
		default:
			return nil, fmt.Errorf("no support mode %s", d.networkMode)
		}
	}

	err = mutateNetworks(networks)
	if err != nil {
		return nil, err
	}
	return &pbrpc.CreateEndpointResponse{Interfaces: networks}, nil
}

// deleteVpcEndpoint releases vpc network resources used by Pod.
func (d *daemon) deleteVpcEndpoint(ctx context.Context, req *pbrpc.DeleteEndpointRequest) (resp *pbrpc.DeleteEndpointResponse, err error) {
	lg := log.WithFields(logger.Fields{
		"Namespace":          req.Namespace,
		"Name":               req.Name,
		"SandboxContainerId": req.InfraContainerId,
	})
	lg.InfoS("Handle DeleteEndpoint")
	defer runtime.HandleCrash(lg)
	defer func() {
		if err != nil {
			lg.ErrorS(err, "Fail to handle DeleteEndpoint")
		} else {
			lg.InfoS("Handle DeleteEndpoint succeed")
		}
	}()

	_, exist := d.pendingPods.LoadOrStore(types.PodKey(req.Namespace, req.Name), struct{}{})
	if exist {
		return nil, fmt.Errorf("pod %s request processing", types.PodKey(req.Namespace, req.Name))
	}
	defer func() {
		d.pendingPods.Delete(types.PodKey(req.Namespace, req.Name))
	}()

	start := time.Now()
	defer func() {
		metrics.RpcLatency.WithLabelValues("DeleteEndpoint", fmt.Sprint(err != nil)).Observe(metrics.MsSince(start))
	}()

	oldPod, err := d.podPersistenceManager.Get(req.Namespace, req.Name)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		} else {
			return &pbrpc.DeleteEndpointResponse{}, nil
		}
	}
	// check containerId, since pod of stateful maybe has same name
	if oldPod.SandboxContainerId != req.InfraContainerId {
		return &pbrpc.DeleteEndpointResponse{}, nil
	}

	netCtx := &netContext{
		Context: ctx,
		pod:     oldPod,
		log:     lg,
	}

	k8sPod, err := d.k8s.GetCachedPod(req.Namespace, req.Name)
	if err != nil && !apiErrors.IsNotFound(err) {
		return nil, fmt.Errorf("get pod from cache failed, %v", err)
	}

	newPod := d.translatePod(k8sPod)
	if newPod != nil && !d.verifyPodNetwork(newPod.PodNetworkMode) {
		return nil, fmt.Errorf("pod network mode not match with daemon")
	}

	for i, r := range oldPod.Resources {
		mgr := d.managers[r.Type]
		if mgr == nil {
			lg.ErrorS(nil, "Find resource without manger", "Type", r.Type)
			continue
		}
		err = mgr.Release(netCtx, &oldPod.Resources[i])
		if err != nil && !errors.Is(err, pool.ErrResourceInvalid) {
			return nil, fmt.Errorf("release resource %s[Type: %s] failed, %v", r.ID, r.Type, err)
		}
		err = d.podPersistenceManager.Delete(oldPod.Namespace, oldPod.Name)
		if err != nil {
			return nil, fmt.Errorf("delete pod from db failed, %v", err)
		}
	}
	return &pbrpc.DeleteEndpointResponse{}, nil
}

// GetPodMetaInfo returns Pod metadata.
func (d *daemon) GetPodMetaInfo(ctx context.Context, request *pbrpc.GetPodMetaRequest) (*pbrpc.GetPodMetaResponse, error) {
	defer runtime.HandleCrash(log)
	pod, err := d.k8s.GetCachedPod(request.GetNamespace(), request.GetName())
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
func (d *daemon) PatchPodAnnotation(ctx context.Context, request *pbrpc.PatchPodAnnotationRequest) (*pbrpc.PatchPodAnnotationResponse, error) {
	defer runtime.HandleCrash(log)
	return &pbrpc.PatchPodAnnotationResponse{}, d.k8s.PatchPodAnnotation(ctx, request.GetNamespace(), request.GetName(), request.GetAnnotations())
}

func (d *daemon) verifyPodNetwork(podNetworkMode string) bool {
	return (d.networkMode == config.NetworkModeENIExclusive && podNetworkMode == types.PodNetworkModeENIExclusive) ||
		(d.networkMode == config.NetworkModeENIShare && podNetworkMode == types.PodNetworkModeENIShare)
}

func (d *daemon) syncPodPersistence() error {
	log.InfoS("Sync pod persistence")
	podMap := map[string]*v1.Pod{}

	persistPods, err := d.podPersistenceManager.List()
	if err != nil {
		return fmt.Errorf("list persist pods failed: %w", err)
	}

	localPods, err := d.k8s.ListCachedPods()
	if err != nil {
		return fmt.Errorf("list local pods failed: %w", err)
	}

	for _, pod := range localPods {
		podMap[types.PodKey(pod.Namespace, pod.Name)] = pod
	}

	for _, pod := range persistPods {
		if _, exist := podMap[types.PodKey(pod.Namespace, pod.Name)]; exist {
			continue
		}

		if pod.NetNs != "" {
			// check pod ns
			if exist, inErr := netns.CheckNetNsExist(pod.NetNs); inErr == nil && exist {
				continue
			}
		}

		log.WarnS("Found pod in persistence not exist in k8s, it would be deleted.", "ns", pod.Namespace, "name", pod.Name)
		err = d.podPersistenceManager.Delete(pod.Namespace, pod.Name)
		if err != nil {
			return fmt.Errorf("delete pod[%s] in persistence failed: %w", pod.Name, err)
		}
	}
	return nil
}

func (d *daemon) startServers(stopCh chan struct{}) error {
	log.InfoS("Cello daemon ready, start service")

	err := d.devicePluginManager.Serve(stopCh)
	if err != nil {
		return fmt.Errorf("device plugin start failed: %v", err)
	}
	defer d.devicePluginManager.Stop()

	grpcServer, err := d.startEndpointGrpcServer()
	if err != nil {
		return fmt.Errorf("start grpc server failed: %v", err)
	}
	defer grpcServer.Stop()

	debugServer, err := d.startDebugServer()
	if err != nil {
		return fmt.Errorf("start debug server failed: %v", err)
	}
	defer func(debugServer *http.Server) {
		inErr := debugServer.Close()
		if inErr != nil {
			log.ErrorS(inErr, "DebugServer close failed")
		}
	}(debugServer)

	ctlApi := d.newCelloCtlAPI()
	ctlServer, err := ctlApi.start()
	if err != nil {
		return fmt.Errorf("startcello ctl handler failed, %v", err)
	}
	defer func(ctlServer *http.Server) {
		inErr := ctlServer.Close()
		if inErr != nil {
			log.ErrorS(inErr, "CtlServer close failed")
		}
	}(ctlServer)

	<-stopCh
	return nil
}

func listenOnUnixSock(socketFilePath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketFilePath), 0700); err != nil {
		return nil, err
	}

	if err := syscall.Unlink(socketFilePath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	mask := syscall.Umask(0777)
	defer syscall.Umask(mask)

	l, err := net.Listen("unix", socketFilePath)
	if err != nil {
		return nil, fmt.Errorf("error listen at %s: %v", socketFilePath, err)
	}
	return l, nil
}

func (d *daemon) startEndpointGrpcServer() (*grpc.Server, error) {
	// 启动http server, 用于cni gPRC server
	l, err := listenOnUnixSock(d.apiListenAddress)
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer()
	pbrpc.RegisterCelloServer(grpcServer, d)

	go func() {
		log.InfoS("Start grpc server")
		err = grpcServer.Serve(l)
		if err != nil {
			log.ErrorS(err, "Grpc server exit")
		}
	}()
	return grpcServer, nil
}

// In the future, we hope that startDebugServer and startCliServer can be merged
func (d *daemon) startDebugServer() (*http.Server, error) {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "ok")
	})
	serveMux.HandleFunc("/debug/pprof", redirectTo("/debug/pprof/"))
	serveMux.HandleFunc("/debug/pprof/", pprof.Index)
	serveMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	serveMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	serveMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	metrics.ServeMetrics(serveMux)

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(int(*config.Config.HeathAndDebugPort)),
		Handler:      serveMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		defer runtime.HandleCrash(log)
		log.InfoS("Start debug server")
		err := server.ListenAndServe()
		if err != nil {
			log.ErrorS(err, "Debug server exit")
		}
	}()

	return server, nil
}

func redirectTo(to string) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, to, http.StatusFound)
	}
}

func (d *daemon) getTrunkENI() *types.ENI {
	var trunk *types.ENI
	switch d.networkMode {
	case config.NetworkModeENIExclusive:
		if d.eniManager != nil {
			trunk = d.eniManager.trunkEni
		}
	case config.NetworkModeENIShare:
		if d.eniIPManager != nil {
			trunk = d.eniIPManager.trunkEni
		}
	}
	return trunk
}

func (d *daemon) networkFromCRD(pod *types.Pod) ([]*pbrpc.NetworkInterface, error) {
	if !pod.VpcENI {
		return nil, nil
	}
	var networksStr string
	var network types.PodNetwork
	var exist bool
	err := wait.ExponentialBackoff(backoff.BackOff(backoff.WaitCRDStatus), func() (bool, error) {
		k8sPod, inErr := d.k8s.GetCachedPod(pod.Namespace, pod.Name)
		if inErr != nil {
			if apiErrors.IsNotFound(inErr) {
				return false, inErr
			} else {
				return false, nil
			}
		}
		annotations := k8sPod.GetAnnotations()
		if annotations == nil {
			return false, nil
		}

		if networksStr, exist = annotations[types.AnnotationVKEPodNetworks]; !exist {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("wait networks from crd failed, %s", err.Error())
	}
	err = json.Unmarshal([]byte(networksStr), &network)
	if err != nil {
		return nil, err
	}
	trunkENI := d.getTrunkENI()
	if trunkENI == nil || network.TrunkENIId != trunkENI.ID {
		return nil, fmt.Errorf("not match")
	}

	return []*pbrpc.NetworkInterface{
		{
			ENI: &pbrpc.ENI{
				ID:          network.ENIId,
				Mac:         trunkENI.Mac.String(),
				IPv4Gateway: network.Gateway.GetIPv4(),
				IPv6Gateway: network.Gateway.GetIPv6(),
				Subnet:      network.Cidr,
				Trunk:       true,
				Vid:         network.VlanID,
				SlaveMac:    network.Mac,
			},
			IPv4Addr:     network.PodIP.IPv4,
			IPv6Addr:     network.PodIP.IPv6,
			IfName:       network.IfName,
			ExtraRoutes:  nil,
			DefaultRoute: true,
		},
	}, nil
}

func mutateNetworks([]*pbrpc.NetworkInterface) error {
	return nil
}

func IsMain(ifName string) bool {
	return ifName == "" || ifName == types.DefaultIfName
}

func (d *daemon) translatePod(pod *v1.Pod) *types.Pod {
	if pod == nil {
		return nil
	}
	result := &types.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}

	if vpcENI, ok := pod.Annotations[types.AnnotationPodNetworksDefinition]; ok {
		var err error
		result.VpcENI, err = strconv.ParseBool(vpcENI)
		if err != nil {
			_ = tracing.RecordPodEvent(pod.Name, pod.Namespace, v1.EventTypeWarning,
				"ParsePodFailed", fmt.Sprintf("Parse vpc eni %s failed.", vpcENI))
		}
	}

	if value, ok := pod.Annotations[types.AnnotationEvictionPolicyKey]; ok {
		result.AllowEviction = value == types.AllowEviction
	}

	if d.networkMode == config.NetworkModeENIShare {
		result.PodNetworkMode = types.PodNetworkModeENIShare
	}
	if d.networkMode == config.NetworkModeENIExclusive {
		result.PodNetworkMode = types.PodNetworkModeENIExclusive
	}

	return result
}

func (d *daemon) GetStockPodCount() int {
	var count int
	pods, err := d.k8s.ListCachedPods()
	if err != nil {
		log.ErrorS(err, "List cached pods failed")
		return count
	}
	for _, pod := range pods {
		if _, err = d.podPersistenceManager.Get(pod.Namespace, pod.Name); err == nil && !isHostNetwork(pod) && !hasRequestAndLimitsFields(pod) {
			count++
		}
	}
	return count
}

func isHostNetwork(pod *v1.Pod) bool {
	return pod.Spec.HostNetwork
}

func hasRequestAndLimitsFields(pod *v1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Resources.Requests != nil {
			_, ok := c.Resources.Requests[deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName]
			if ok {
				return true
			}
			_, ok = c.Resources.Requests[deviceplugin.VolcNameSpace+deviceplugin.ENIIPResourceName]
			if ok {
				return true
			}
			_, ok = c.Resources.Requests[deviceplugin.VolcNameSpace+deviceplugin.BranchENIResourceName]
			if ok {
				return true
			}
		}
	}
	return false
}

func watchResourceNum(ctx context.Context, pluginManger deviceplugin.Manager, resName string, lister func() int, updateSignal <-chan struct{}) {
	// A ticker for resync resourceNum
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	var err error
	for {
		select {
		case <-ticker.C:
			err = pluginManger.Update(resName, lister())
		case <-updateSignal:
			err = pluginManger.Update(resName, lister())
		case <-ctx.Done():
			return
		}
		if err != nil {
			log.ErrorS(err, "update resource", "resName", resName)
		}
	}
}

// getInstanceProject get ProjectName of ecs instance
func getInstanceProject(ec2Client ec2.APIGroupECS, instanceMeta helper.InstanceMetadataGetter) (string, error) {
	var inErr error
	var output *ecs.DescribeInstancesOutput
	err := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		output, inErr = ec2Client.DescribeInstances(&ecs.DescribeInstancesInput{
			VpcId:       volcengine.String(instanceMeta.GetVpcId()),
			InstanceIds: []*string{volcengine.String(instanceMeta.GetInstanceId())},
		})
		if inErr != nil {
			return false, nil
		}
		return true, nil
	})
	if err = apiErr.BackoffErrWrapper(err, inErr); err != nil {
		return "", fmt.Errorf("desribe instance failed, %v", err)
	}
	if output == nil || len(output.Instances) != 1 {
		return "", fmt.Errorf("desribe instance failed, no result")
	}
	return datatype.StringValue(output.Instances[0].ProjectName), nil
}
