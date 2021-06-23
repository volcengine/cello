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

package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/metrics"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/utils/math"
	"github.com/volcengine/cello/types"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "pool"})

var (
	ErrContextDone               = errors.New("context done")
	ErrNoResourceAvailableInPool = errors.New("no resource available in pool, applying")
	ErrNoResourceAvailable       = errors.New("no resource available, check quota")
	ErrResourceInvalid           = errors.New("resource state invalid")

	defaultPoolBackoffPeriod = 5 * time.Second
	maxPoolBackoffPeriod     = 1 * time.Minute
)

type ObjectFactory interface {
	// Name of ObjectFactory
	Name() string

	// Create a certain amount of resources
	Create(count int) ([]types.NetResource, error)

	// Release destroy resource
	Release(resource types.NetResource) error

	// ReleaseInValid destroy invalid resource
	ReleaseInValid(resource types.NetResource) (types.NetResource, error)

	// Valid check if the resource is valid
	Valid(resource types.NetResource) error

	// List all resource created by ObjectFactory
	List() (map[types.ResStatus]map[string]types.NetResource, error)

	// GC sync objects in ObjectFactory with remote provider
	GC() error

	// GetResourceLimit get the maximum number of resources that can be created by ObjectFactory
	GetResourceLimit() int
}

type ResourcePool interface {
	// Name of ResourcePool
	Name() string

	// Allocate a specified or available types.NetResource from pool
	// If no resources are available in ResourcePool, create one
	Allocate(ctx context.Context, prefer, owner string) (types.NetResource, error)

	// Release a specified resource by ID
	Release(resID string) error

	// Status get Status of ResourcePool
	Status() Status

	// GetSnapshot get snapshot of ResourcePool
	GetSnapshot() (ResourcePoolSnapshot, error)

	// GC sync resource in ResourcePool with resource in ObjectFactory
	GC(getAllocatedResMap func() (map[string]types.NetResourceAllocated, error)) error // resourceId -- vpcResource

	// GetResourceLimit get the maximum number of resources that can be created by ObjectFactory
	GetResourceLimit() int

	// ReCfgCache reconfigure pooling parameters
	ReCfgCache(target, targetMin int)
}

type ResourcePoolSnapshot interface {
	// PoolSnapshot snapshot of pool
	PoolSnapshot() map[string]types.NetResourceStatus

	// MetaSnapshot snapshot of ObjectFactory
	MetaSnapshot() map[string]types.NetResourceStatus
}

type ResourcePoolSnapshotCache struct {
	Pool map[string]types.NetResourceStatus
	Meta map[string]types.NetResourceStatus
}

func (r *ResourcePoolSnapshotCache) PoolSnapshot() map[string]types.NetResourceStatus {
	return r.Pool
}

func (r *ResourcePoolSnapshotCache) MetaSnapshot() map[string]types.NetResourceStatus {
	return r.Meta
}

type ResourcePoolOp interface {
	// AddInuse add a used resource to pool
	AddInuse(res types.NetResource, owner string)

	// AddInvalid add an invalid resource to pool
	AddInvalid(res types.NetResource)

	// AddAvailable add a available resource to pool
	AddAvailable(res types.NetResource)
}

type ResourcePoolHook func(pool ResourcePoolOp) error

type poolItem struct {
	owner         string
	res           types.NetResource
	lastUse       time.Time
	reserveBefore time.Time
}

type poolImpl struct {
	name      string
	resType   string
	inUse     map[string]poolItem // id <--> item
	available *priorityQueue
	invalid   map[string]poolItem // id <--> item, cant use and wait to release
	factory   ObjectFactory

	mutex     sync.Mutex
	pauseLock sync.RWMutex

	// concurrency control
	ticket  chan struct{}
	backoff time.Duration

	scale chan struct{}

	// config
	poolConfigInner

	// metrics
	metricAvailable prometheus.Gauge
	metricTotal     prometheus.Gauge
	logger.Logger
}

func (p *poolImpl) backoffCallFactory() {
	if p.backoff < maxPoolBackoffPeriod {
		p.backoff = p.backoff * 2
	}
}

func (p *poolImpl) backoffReset() {
	p.backoff = defaultPoolBackoffPeriod
}

func (p *poolImpl) lock() {
	p.mutex.Lock()
}

func (p *poolImpl) unlock() {
	p.mutex.Unlock()
}

func (p *poolImpl) blockPause() {
	p.pauseLock.RLock()
}

func (p *poolImpl) unblockPause() {
	p.pauseLock.RUnlock()
}

func (p *poolImpl) pause() {
	// order matters !!
	p.pauseLock.Lock()
	p.mutex.Lock()
}

func (p *poolImpl) unpause() {
	p.mutex.Unlock()
	p.pauseLock.Unlock()
}

func (p *poolImpl) Name() string {
	return p.name
}

func (p *poolImpl) AddInuse(res types.NetResource, owner string) {
	p.lock()
	defer p.unlock()
	p.Debugf("Add resource %s to pool inuse", res.GetID())
	p.inUse[res.GetID()] = poolItem{
		owner:   owner,
		res:     res,
		lastUse: time.Now(),
	}
	p.metricTotal.Inc()
}

func (p *poolImpl) AddInvalid(res types.NetResource) {
	p.lock()
	defer p.unlock()
	p.Debugf("Add resource %s to pool invalid", res.GetID())
	p.invalid[res.GetID()] = poolItem{
		res: res,
	}
	p.metricTotal.Inc()
}

func (p *poolImpl) AddAvailable(res types.NetResource) {
	p.lock()
	defer p.unlock()
	p.Debugf("Add resource %s to pool available", res.GetID())
	p.available.Push(&poolItem{
		res:           res,
		reserveBefore: time.Now(),
	})
	p.metricAvailable.Inc()
	p.metricTotal.Inc()
}

// capWithLocked return cap of pool, it needs to be used locked.
func (p *poolImpl) capWithLocked() int {
	return len(p.inUse) + p.available.Size() + len(p.invalid)
}

func (p *poolImpl) notifyScale() {
	select {
	case p.scale <- struct{}{}:
	default:
	}
}

func (p *poolImpl) productTicket() {
	select {
	case p.ticket <- struct{}{}:
	default:
	}
}

func (p *poolImpl) allocateFromPool(prefer, owner string) (types.NetResource, error) {
	p.lock()
	defer p.unlock()

	lg := p.WithFields(logger.Fields{"prefer": prefer, "owner": owner})
	if item, exist := p.inUse[prefer]; exist && item.owner == owner {
		return item.res, nil
	}

	if p.available.Size() > 0 {
		item := p.available.PopPrefer(prefer)
		if item == nil {
			return nil, apiErr.ErrNotFound
		}
		res := item.res
		p.inUse[res.GetID()] = poolItem{
			owner:   owner,
			lastUse: time.Now(),
			res:     res,
		}
		p.metricAvailable.Dec()
		lg.Infof("Allocate resource from pool success: %s", res.GetID())
		p.notifyScale()
		return res, nil
	}

	if curCap := p.capWithLocked(); curCap >= p.getMaxCap() {
		lg.Warnf("Allocate resource from pool failed: %s (current cap: %d, max cap: %d)",
			ErrNoResourceAvailable, curCap, p.getMaxCap())
		return nil, ErrNoResourceAvailable
	}

	return nil, ErrNoResourceAvailableInPool
}

func (p *poolImpl) Allocate(ctx context.Context, prefer, owner string) (types.NetResource, error) {
	lg := p.WithFields(logger.Fields{"prefer": prefer, "owner": owner})

	for {
		res, err := p.allocateFromPool(prefer, owner)
		if err == nil {
			return res, nil
		}
		if !errors.Is(err, ErrNoResourceAvailableInPool) {
			return nil, err
		}

		select {
		case <-ctx.Done():
			lg.Infof("Allocate resource return because %s", ErrContextDone)
			return nil, ErrContextDone
		case <-p.ticket:
			exec := func() (types.NetResource, error) {
				p.blockPause()
				defer p.unblockPause()
				resources, err := p.factory.Create(1)
				if err != nil || len(resources) == 0 {
					p.productTicket()
					lg.Errorf("Factory create resource err: %v", err)
					return nil, fmt.Errorf("factory create resource err: %v", err)
				}
				p.AddInuse(resources[0], owner)
				lg.Infof("Allocate resource from pool success after create: %s", resources[0].GetID())
				return resources[0], nil
			}
			return exec()
		default:
			time.Sleep(defaultPoolBackoffPeriod)
		}
	}
}

func (p *poolImpl) Release(resID string) error {
	p.lock()
	defer p.unlock()

	item, exist := p.inUse[resID]
	if !exist {
		p.Errorf("Find resource %s not exist in pool", resID)
		return ErrResourceInvalid
	}
	delete(p.inUse, resID)

	err := p.factory.Valid(item.res)
	if err != nil {
		// try to delete
		var temp types.NetResource
		temp, err = p.factory.ReleaseInValid(item.res)
		if temp == nil && err == nil {
			p.productTicket()
			p.metricTotal.Dec()
			return nil
		}
		if temp != nil {
			p.Warnf("Convert invalid resource %s to valid %s", resID, temp.GetID())
			p.available.Push(&poolItem{
				res:           temp,
				reserveBefore: time.Now(),
			})
			p.metricAvailable.Inc()
			return nil
		}
		p.Warnf("Destroy resource %v failed: %v", item.res, err)
		p.invalid[resID] = item
		return nil
	}
	p.Infof("Release resource to pool %s success", resID)
	p.available.Push(&poolItem{
		res:           item.res,
		reserveBefore: time.Now(),
	})
	p.metricAvailable.Inc()
	return nil
}

func (p *poolImpl) Status() Status {
	p.lock()
	defer p.unlock()

	cur := p.available.Size()
	cnt := math.Max(p.getTarget()-cur, 0)
	cur += len(p.inUse)
	cnt = math.Max(cnt, p.getTargetMin()-cur)
	cur += len(p.invalid)
	cnt = math.Min(cnt, p.getMaxCap()-cur)
	short := math.Max(0, cnt)

	over := math.Max(p.available.Size()-p.getTarget(), 0)
	over = math.Max(math.Min(over, cur-p.getTargetMin()), 0)

	return Status{
		TargetMin:       p.getTargetMin(),
		Target:          p.getTarget(),
		MaxCap:          p.getMaxCap(),
		MaxCapProbe:     p.getMaxCapProbe(),
		MonitorInterval: p.getMonitorInterval(),
		Total:           cur,
		Available:       p.available.Size(),
		Short:           short,
		Over:            over,
	}
}

func (p *poolImpl) GetResourceLimit() int {
	return p.factory.GetResourceLimit()
}

func (p *poolImpl) resetTicketWithLocked() {
out:
	for {
		select {
		case <-p.ticket:
		default:
			break out
		}
	}
	cnt := p.getMaxCap() - p.capWithLocked()
	for i := 0; i < cnt; i++ {
		p.productTicket()
	}
}

func (p *poolImpl) shouldIncrease() int {
	p.lock()
	defer p.unlock()
	cur := p.available.Size()
	cnt := math.Max(p.getTarget()-cur, 0)
	cur += len(p.inUse)
	cnt = math.Max(cnt, p.getTargetMin()-cur)
	cur += len(p.invalid)
	cnt = math.Min(cnt, p.getMaxCap()-cur)
	return math.Max(0, cnt)
}

func (p *poolImpl) tryIncreasePool() {
	p.Debugf("Try Increase pool")
	toIncrease := p.shouldIncrease()
	if toIncrease <= 0 {
		return
	}
	toCreate := 0
	// increase
	for i := 0; i < toIncrease; i++ {
		select {
		case <-p.ticket:
			toCreate++
		default:
			continue
		}
	}
	p.Infof("Try create %d resource", toCreate)
	if toCreate > 0 {
		res, err := p.factory.Create(toCreate)
		if err != nil {
			p.Errorf("Create resource failed: %v, backoff: %v", err, p.backoff)
			defer func() {
				p.backoffCallFactory()
				time.Sleep(p.backoff)
			}()
		}
		if len(res) == toCreate {
			p.backoffReset()
		} else {
			p.Warnf("Resource created: %d, expected: %d", len(res), toCreate)
		}
		releaseTickets := math.Max(0, toCreate-len(res))
		for i := 0; i < releaseTickets; i++ {
			p.productTicket()
		}
		if releaseTickets != 0 { // part failed, try again
			p.notifyScale()
		}
		for _, item := range res {
			p.AddAvailable(item)
		}
		p.Infof("%d resource increased", len(res))
	}
}

func (p *poolImpl) popOverflow() *poolItem {
	p.lock()
	defer p.unlock()

	var item *poolItem
	if (p.available.Size() > p.getTarget() &&
		p.available.Size()+len(p.inUse) > p.getTargetMin()) ||
		p.capWithLocked() > p.getMaxCap() {
		item = p.available.Peek()
	}
	if item != nil && item.reserveBefore.Before(time.Now()) {
		return p.available.Pop()
	}
	return nil
}

func (p *poolImpl) tryReducePool() {
	p.Debugf("Try Reduce pool")
	var reAvailable []types.NetResource
	for {
		item := p.popOverflow()
		if item == nil {
			break
		}
		p.metricTotal.Dec()
		p.metricAvailable.Dec()
		err := p.factory.Release(item.res)
		if err == nil {
			p.Infof("Destroy resource %v succeed", item.res)
			p.productTicket()
			p.backoffReset()
		} else if errors.Is(err, apiErr.ErrInvalidDeletionPrimaryIP) {
			reAvailable = append(reAvailable, item.res)
		} else {
			p.Warnf("Destroy resource %v failed: %v, backoff: %v", item.res, err, p.backoff)
			p.backoffCallFactory()
			p.AddAvailable(item.res)
			time.Sleep(p.backoff)
		}
	}

	for _, res := range reAvailable {
		p.AddAvailable(res)
	}
}

func (p *poolImpl) checkInvalid() {
	p.lock()
	defer p.unlock()

	for id, invalid := range p.invalid {
		lg := p.WithFields(map[string]interface{}{
			"id":     invalid.res.GetID(),
			"reason": "invalid",
		})
		ret, err := p.factory.ReleaseInValid(invalid.res)
		if err != nil {
			lg.Warnf("Release invalid resource %v failed, %v", invalid.res, err)
			continue
		}
		delete(p.invalid, id)
		if ret != nil {
			p.available.Push(&poolItem{
				res:           ret,
				reserveBefore: time.Now(),
			})
			p.metricAvailable.Inc()
			lg.Infof("Release invalid resource succeed and get new one: %s", ret.GetID())
		} else {
			p.metricTotal.Dec()
			p.productTicket()
			lg.Infof("Release invalid resource succeed")
		}
	}
}

func (p *poolImpl) GetSnapshot() (ResourcePoolSnapshot, error) {
	p.lock()
	defer p.unlock()

	pool := map[string]types.NetResourceStatus{}
	meta := map[string]types.NetResourceStatus{}
	for id, item := range p.invalid {
		pool[id] = &types.NetResourceSnapshot{
			VPCResource: item.res.GetVPCResource(),
			Status:      types.ResStatusInvalid,
		}
	}
	for id, item := range p.inUse {
		pool[id] = &types.NetResourceSnapshot{
			Owner:       item.owner,
			VPCResource: item.res.GetVPCResource(),
			Status:      types.ResStatusInUse,
		}
	}

	for _, item := range p.available.innerQueue {
		res := item.res
		pool[res.GetID()] = &types.NetResourceSnapshot{
			VPCResource: res.GetVPCResource(),
			Status:      types.ResStatusAvailable,
		}
	}

	list, err := p.factory.List()
	if err != nil {
		return nil, err
	}
	for _, item := range list[types.ResStatusNormal] {
		status := types.ResStatusNotAdded
		owner := ""
		if poolRes, exist := pool[item.GetID()]; exist {
			status = poolRes.GetStatus()
			owner = poolRes.GetOwner()
		}
		meta[item.GetID()] = &types.NetResourceSnapshot{
			Owner:       owner,
			VPCResource: item.GetVPCResource(),
			Status:      status,
		}
	}

	for _, item := range list[types.ResStatusInvalid] {
		owner := ""
		if poolRes, exist := pool[item.GetID()]; exist {
			owner = poolRes.GetOwner()
		}
		meta[item.GetID()] = &types.NetResourceSnapshot{
			VPCResource: item.GetVPCResource(),
			Status:      types.ResStatusInvalid,
			Owner:       owner,
		}
	}

	for _, item := range list[types.ResStatusLegacy] {
		owner := ""
		if poolRes, exist := pool[item.GetID()]; exist {
			owner = poolRes.GetOwner()
		}
		meta[item.GetID()] = &types.NetResourceSnapshot{
			VPCResource: item.GetVPCResource(),
			Status:      types.ResStatusLegacy,
			Owner:       owner,
		}
	}

	return &ResourcePoolSnapshotCache{
		Pool: pool,
		Meta: meta,
	}, nil
}

func (p *poolImpl) worker() {
	cycle := make(chan struct{})
	go wait.JitterUntil(func() {
		cycle <- struct{}{}
	}, p.getMonitorInterval(), 0.2, true, wait.NeverStop)

	for {
		select {
		case <-p.scale:
			p.blockPause()
			p.tryIncreasePool()
			p.unblockPause()
		case <-cycle:
			p.blockPause()
			p.checkInvalid()
			p.tryIncreasePool()
			p.tryReducePool()
			p.unblockPause()
		}
	}
}

func (p *poolImpl) init() error {
	p.lock()
	defer p.unlock()

	p.resetTicketWithLocked()
	return nil
}

func (p *poolImpl) GC(getAllocatedResMap func() (map[string]types.NetResourceAllocated, error)) error {
	p.pause()
	defer p.unpause()
	usedResource, err := getAllocatedResMap()
	if err != nil {
		return err
	}
	p.Debugf("GC start, usedResource: %v", usedResource)
	err = p.factory.GC()
	if err != nil {
		return fmt.Errorf("factory gc failed, %v", err)
	}

	list, err := p.factory.List()
	if err != nil {
		return fmt.Errorf("factory list failed, %v", err)
	}

	p.WithFields(logger.Fields{"phase": "before gc"}).Debugf("Factory items: %v", list)
	p.WithFields(logger.Fields{"phase": "before gc"}).Debugf("Inuse items in pool: %v", p.inUse)
	p.WithFields(logger.Fields{"phase": "before gc"}).Debugf("Available items in pool: %v", p.available.Dump())
	p.WithFields(logger.Fields{"phase": "before gc"}).Debugf("Invalid items in pool: %v", p.invalid)
	// sync resource member
	for id, item := range p.inUse {
		if local, exist := usedResource[id]; !exist {
			if time.Since(item.lastUse) > p.getGcProtectPeriod() {
				p.Warnf("Release %v which used by %s once", item.res.GetVPCResource(), item.owner)
				delete(p.inUse, id)
			}
		} else {
			if local.Owner == item.owner {
				delete(usedResource, id)
			}
		}
	}
	for id, res := range usedResource {
		for _, resMap := range list {
			if item, exist := resMap[id]; exist {
				p.inUse[id] = poolItem{
					owner: res.Owner,
					res:   item,
				}
			}
		}
	}

	p.invalid = map[string]poolItem{}
	for id, item := range list[types.ResStatusInvalid] {
		if _, exist := p.inUse[id]; !exist {
			p.invalid[id] = poolItem{
				res: item,
			}
		}
	}
	for id, item := range list[types.ResStatusLegacy] {
		if _, exist := p.inUse[id]; !exist {
			p.invalid[id] = poolItem{
				res: item,
			}
		}
	}

	oldAvailable := p.available.Dump()
	p.available = newPriorityQueue()
	for id, item := range list[types.ResStatusNormal] {
		if _, exist := p.inUse[id]; !exist {
			poolRes := poolItem{
				res: item,
			}
			if oldItem, ok := oldAvailable[id]; ok {
				poolRes.reserveBefore = oldItem.reserveBefore
			}
			p.available.Push(&poolRes)
		}
	}

	// set metrics
	p.metricAvailable.Set(float64(p.available.Size()))
	p.metricTotal.Set(float64(p.capWithLocked()))
	p.resetTicketWithLocked()

	p.WithFields(logger.Fields{"phase": "after gc"}).Debugf("Inuse items in pool: %v", p.inUse)
	p.WithFields(logger.Fields{"phase": "after gc"}).Debugf("Available items in pool: %v", p.available.Dump())
	p.WithFields(logger.Fields{"phase": "after gc"}).Debugf("Invalid items in pool: %v", p.invalid)
	return nil
}

func (p *poolImpl) ReCfgCache(target, targetMin int) {
	p.Infof("ReConfig pool target and targetMin to %d, %d", target, targetMin)
	p.setTarget(target)
	p.setTargetMin(targetMin)
	p.notifyScale()
}

// NewResourcePool create a ResourcePool according to Config.
func NewResourcePool(config Config) (ResourcePool, error) {
	impl := &poolImpl{
		name:            config.Name,
		resType:         config.Type,
		inUse:           make(map[string]poolItem),
		available:       newPriorityQueue(),
		invalid:         make(map[string]poolItem),
		factory:         config.Factory,
		mutex:           sync.Mutex{},
		pauseLock:       sync.RWMutex{},
		scale:           make(chan struct{}, 1),
		poolConfigInner: config.newPoolConfigInner(),
		metricAvailable: metrics.ResourcePoolAvailable.WithLabelValues(config.Name, config.Type),
		metricTotal:     metrics.ResourcePoolTotal.WithLabelValues(config.Name, config.Type),
		Logger:          log.WithFields(logger.Fields{"pool": config.Name, "factory": config.Factory.Name()}),
	}
	maxCp := impl.getMaxCap()
	impl.ticket = make(chan struct{}, maxCp)
	impl.metricTarget.Set(float64(impl.target))
	impl.metricTargetMin.Set(float64(impl.targetMin))

	if config.PreStart != nil {
		err := config.PreStart(impl)
		if err != nil {
			return nil, err
		}
	}

	err := impl.init()
	if err != nil {
		return nil, fmt.Errorf("resource pool %s init failed: %v", config.Name, err)
	}
	go impl.worker()
	log.WithFields(logger.Fields{
		"Type":            config.Type,
		"MaxCap":          config.MaxCap,
		"Target":          config.Target,
		"TargetMin":       config.TargetMin,
		"MonitorInterval": config.MonitorInterval,
	}).Infof("Resource pool %s start", config.Name)
	return impl, nil
}
