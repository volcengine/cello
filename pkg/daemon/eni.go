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
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/pool"
	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/utils/math"
	"github.com/volcengine/cello/types"
)

const (
	subnetAging = 10 * time.Second
)

// eniResourceManager is the entity to handle ENI resource management.
type eniResourceManager struct {
	pool        pool.ResourcePool
	trunkEni    *types.ENI
	branchLimit int
}

func (e *eniResourceManager) Name() string {
	return "eni resource manager"
}

// Allocate allocates an ENI resource.
func (e *eniResourceManager) Allocate(ctx *netContext, prefer string) (types.NetResource, error) {
	res, err := e.pool.Allocate(ctx, prefer, types.PodKey(ctx.pod.Namespace, ctx.pod.Name))
	if err != nil {
		ctx.Log().Errorf("Allocate failed, %v", err)
		return nil, err
	}
	ctx.Log().Infof("Allocate succeed: %v", res)
	return res, nil
}

// Release releases an ENI resource.
func (e *eniResourceManager) Release(ctx *netContext, resource *types.VPCResource) error {
	err := e.pool.Release(resource.ID)
	if err != nil {
		ctx.Log().Errorf("Release %v failed, %v", resource, err)
		return err
	}
	ctx.Log().Infof("Release %v succeed", resource)
	return nil
}

// GetSnapshot returns the snapshot of ENI resource pool.
func (e *eniResourceManager) GetSnapshot() (pool.ResourcePoolSnapshot, error) {
	return e.pool.GetSnapshot()
}

// GetPoolStatus returns the status of ENI resource pool.
func (e *eniResourceManager) GetPoolStatus() pool.Status {
	return e.pool.Status()
}

// GetResourceLimit returns the limit of ENI resource pool.
func (e *eniResourceManager) GetResourceLimit() int {
	return e.pool.GetResourceLimit()
}

func (e *eniResourceManager) GetTrunkBranchLimit() int {
	return e.branchLimit
}

func (e *eniResourceManager) SupportTrunk() bool {
	return e.trunkEni != nil
}

func generateENIPoolCfg(cfg *config.Config, limits helper.InstanceLimits) pool.Config {
	*cfg.EnableTrunk = *cfg.EnableTrunk && limits.TrunkSupported
	if *cfg.PoolTargetLimit > 1 {
		*cfg.PoolTargetLimit = 1
	}

	totalMax := int(*cfg.PoolMaxCap)
	if *cfg.PoolMaxCapProbe {
		totalMax = limits.ENIAvailable()
	}

	target := math.Min(int(*cfg.PoolTarget), math.Floor(*cfg.PoolTargetLimit*float64(totalMax)))
	targetMin := math.Min(int(*cfg.PoolTargetMin), math.Floor(*cfg.PoolTargetLimit*float64(totalMax)))

	return pool.Config{
		Name:            "eni",
		Type:            types.NetResourceTypeEni,
		TargetMin:       targetMin,
		Target:          target,
		MaxCap:          totalMax,
		MaxCapProbe:     *cfg.PoolMaxCapProbe,
		MonitorInterval: time.Duration(*cfg.PoolMonitorIntervalSec) * time.Second,
		GCProtectPeriod: time.Duration(*cfg.PoolGCProtectPeriodSec) * time.Second,
	}
}

func newEniResourceManager(cfg *config.Config, subnet helper.SubnetManager, secManager helper.SecurityGroupManager, volcApi helper.VolcAPI, allocatedResource map[string]types.NetResourceAllocated, k8s k8s.Service) (*eniResourceManager, error) {
	log.Infof("Creating EniResourceManager")
	m := &eniResourceManager{}
	limit, err := helper.NewInstanceLimitManager(volcApi)
	if err != nil {
		return nil, err
	}
	poolConfig := generateENIPoolCfg(cfg, limit.GetLimit())
	created, err := volcApi.GetAttachedENIs(false)
	if err != nil {
		return nil, fmt.Errorf("get attached enis failed while init, %v", err)
	}

	factory, err := newEniFactory(secManager, subnet, volcApi, limit, types.IPFamily(*cfg.IPFamily))
	if err != nil {
		return nil, fmt.Errorf("create eni factory failed, %v", err)
	}
	poolConfig.Factory = factory

	// Trunk
	m.trunkEni = limit.GetLimit().TrunkENI
	if *cfg.EnableTrunk && m.trunkEni == nil {
		res, err := factory.CreateWithIPCount(1, true)
		if err != nil {
			return nil, fmt.Errorf("alloc trunk eni failed, %v", err)
		}
		m.trunkEni = res.(*types.ENI)
		limit.UpdateTrunk(m.trunkEni)
	}

	poolConfig.PreStart = func(pool pool.ResourcePoolOp) error {
		for _, e := range created {
			if item, exist := allocatedResource[e.GetID()]; exist {
				pool.AddInuse(e, item.Owner)
			} else {
				pool.AddAvailable(e)
			}
		}
		return nil
	}
	factory.monitor(time.Duration(*cfg.SubnetStatUpdateIntervalSec)*time.Second, time.Duration(*cfg.ReconcileIntervalSec)*time.Second)

	p, err := pool.NewResourcePool(poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create resource pool %s failed, %v", poolConfig.Name, err)
	}
	m.pool = p

	if m.trunkEni == nil {
		err = k8s.PatchTrunkInfo(nil)
		m.branchLimit = 0
	} else {
		err = k8s.PatchTrunkInfo(&types.TrunkInfo{
			EniID:       m.trunkEni.GetID(),
			Mac:         m.trunkEni.Mac.String(),
			BranchLimit: limit.GetLimit().ENITotal - limit.GetLimit().ENIQuota,
		})
		m.branchLimit = limit.GetLimit().ENITotal - limit.GetLimit().ENIQuota
	}
	if err != nil {
		return nil, fmt.Errorf("patch trunk info on node failed, %v", err)
	}

	return m, nil
}

// EniFactory is used to manage ENI resources.
type eniFactory struct {
	ipFamily   types.IPFamily
	secManager helper.SecurityGroupManager
	subnets    helper.SubnetManager
	volcApi    helper.VolcAPI
	limit      helper.InstanceLimitManager
}

func (f *eniFactory) Name() string {
	return types.NetResourceTypeEni
}

// Create while create count eni with one ip,
// it will ignore some errors while partially request successful.
func (f *eniFactory) Create(count int) (res []types.NetResource, err error) {
	for i := 0; i < count; i++ {
		var eni types.NetResource
		eni, err = f.CreateWithIPCount(1, false)
		if err == nil {
			res = append(res, eni)
		}
	}
	if len(res) > 0 {
		return res, nil
	}
	return nil, err
}

// CreateWithIPCount create eni with special ip count.
func (f *eniFactory) CreateWithIPCount(ipCnt int, trunk bool) (types.NetResource, error) {
	var err error
	defer func() {
		if err != nil {
			metrics.ResourceManagerErrInc("CreateWithIPCount", err)
		}
	}()
	subnet := f.subnets.SelectSubnet(f.ipFamily, helper.WithAging(subnetAging))
	if subnet == nil {
		f.limit.BlockadeCreate()
		return nil, fmt.Errorf("no available subnet, please check subnets and available ip of subnets")
	}
	f.limit.UnBlockadeCreate()

	eni, err := f.volcApi.AllocENI(subnet.SubnetId, f.secManager.GetSecurityGroups(), trunk, ipCnt)
	if err != nil {
		log.Errorf("Failed to create eni, %v", err)
		if strings.Contains(err.Error(), apiErr.LimitExceededEnisPerInstance) {
			f.limit.Update()
		}
		return nil, err
	}
	log.Infof("Created eni %s", eni.String())
	return eni, nil
}

// ReleaseInValid releases invalid NetResource.
func (f *eniFactory) ReleaseInValid(resource types.NetResource) (types.NetResource, error) {
	return nil, f.Release(resource)
}

// Release releases NetResource.
func (f *eniFactory) Release(resource types.NetResource) error {
	var err error
	defer func() {
		if err != nil {
			metrics.ResourceManagerErrInc("Release", err)
			log.Errorf("Release eni %s failed, %v", resource.GetID(), err)
		} else {
			log.Infof("Release eni %s success", resource.GetID())
		}
	}()
	eni := resource.GetVPCResource()
	err = f.volcApi.FreeENI(eni.ENIId)
	return err
}

// Valid checks if given NetResource is valid.
func (f *eniFactory) Valid(resource types.NetResource) error {
	eni := resource.GetVPCResource()
	_, err := f.volcApi.GetENI(eni.ENIMac)
	return err
}

// List lists all NetResources.
func (f *eniFactory) List() (map[types.ResStatus]map[string]types.NetResource, error) {
	enis, err := f.volcApi.GetAttachedENIs(false)
	if err != nil {
		return nil, err
	}

	list := map[types.ResStatus]map[string]types.NetResource{}
	normal := map[string]types.NetResource{}
	for _, eni := range enis {
		normal[eni.GetID()] = eni
	}
	list[types.ResStatusNormal] = normal
	return list, nil
}

func (f *eniFactory) GC() error {
	return nil
}

// GetResourceLimit returns the limit of NetResource.
func (f *eniFactory) GetResourceLimit() int {
	limit := f.limit.GetLimit()
	return limit.ENIAvailable()
}

func (f *eniFactory) monitor(subnetPeriod, limitPeriod time.Duration) {
	go wait.Forever(func() {
		defer func() {
			if rErr := recover(); rErr != nil {
				log.Errorf("monitor subnet panic, %v", rErr)
			}
		}()
		if subnet := f.subnets.SelectSubnet(f.ipFamily, helper.WithAging(subnetAging)); subnet != nil {
			f.limit.UnBlockadeCreate()
		}
	}, subnetPeriod)
	go wait.Forever(func() {
		defer func() {
			if rErr := recover(); rErr != nil {
				log.Errorf("monitor limit panic, %v", rErr)
			}
		}()
		f.limit.Update()
	}, limitPeriod)
}

func newEniFactory(secManager helper.SecurityGroupManager, subnetManager helper.SubnetManager, api helper.VolcAPI, limit helper.InstanceLimitManager, ipFamily types.IPFamily) (*eniFactory, error) {
	if subnetManager == nil {
		return nil, fmt.Errorf("subnet manager is nil")
	}
	if api == nil {
		return nil, fmt.Errorf("volc api is nil")
	}
	return &eniFactory{
		ipFamily:   ipFamily,
		secManager: secManager,
		subnets:    subnetManager,
		volcApi:    api,
		limit:      limit,
	}, nil
}
