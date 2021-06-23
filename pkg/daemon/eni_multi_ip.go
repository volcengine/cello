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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gdexlab/go-render/render"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/pool"
	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/signal"
	"github.com/volcengine/cello/pkg/utils/ip"
	"github.com/volcengine/cello/pkg/utils/math"
	"github.com/volcengine/cello/types"
)

const (
	// defaultOrderCnt is the default order count.
	defaultOrderCnt = 10
	// defaultEniPending is the default pending ENI count.
	defaultEniPending = 2
)

var ErrLegacy = errors.New("legacy resource")

// eniIPResourceManager is the entity to handle ENI IP resource management.
type eniIPResourceManager struct {
	pool        pool.ResourcePool
	trunkEni    *types.ENI
	branchLimit int
}

func (m *eniIPResourceManager) Name() string {
	return "eniIP resource manager"
}

// Allocate allocates an ENI IP resource.
func (m *eniIPResourceManager) Allocate(ctx *netContext, prefer string) (types.NetResource, error) {
	res, err := m.pool.Allocate(ctx, prefer, types.PodKey(ctx.pod.Namespace, ctx.pod.Name))
	if err != nil {
		ctx.Log().Errorf("Allocate failed, %v", err)
		return nil, err
	}
	ctx.Log().Infof("Allocate succeed: %v", res)
	return res, nil
}

// Release releases an ENI IP resource.
func (m *eniIPResourceManager) Release(ctx *netContext, resource *types.VPCResource) error {
	err := m.pool.Release(resource.ID)
	if err != nil {
		ctx.Log().Errorf("Release %v failed, %v", resource, err)
		return err
	}
	ctx.Log().Infof("Release %v succeed", resource)
	return nil
}

// GetSnapshot returns the snapshot of the resource pool.
func (m *eniIPResourceManager) GetSnapshot() (pool.ResourcePoolSnapshot, error) {
	return m.pool.GetSnapshot()
}

// GetPoolStatus returns the status of the resource pool.
func (m *eniIPResourceManager) GetPoolStatus() pool.Status {
	return m.pool.Status()
}

// GetResourceLimit returns the resource limit of the resource pool.
func (m *eniIPResourceManager) GetResourceLimit() int {
	return m.pool.GetResourceLimit()
}

func (m *eniIPResourceManager) GetTrunkBranchLimit() int {
	return m.branchLimit
}

func (m *eniIPResourceManager) SupportTrunk() bool {
	return m.trunkEni != nil
}

func generateIPPoolCfg(cfg *config.Config, limits helper.InstanceLimits) pool.Config {
	*cfg.EnableTrunk = *cfg.EnableTrunk && limits.TrunkSupported
	if *cfg.PoolTargetLimit > 1 {
		*cfg.PoolTargetLimit = 1
	}

	totalMax := int(*cfg.PoolMaxCap)
	if *cfg.PoolMaxCapProbe {
		totalMax = limits.ENIAvailable() * limits.IPv4MaxPerENI
	}
	target := math.Min(int(*cfg.PoolTarget), math.Floor(*cfg.PoolTargetLimit*float64(totalMax)))
	targetMin := math.Min(int(*cfg.PoolTargetMin), math.Floor(*cfg.PoolTargetLimit*float64(totalMax)))

	return pool.Config{
		Name:            "eniIP",
		Type:            types.NetResourceTypeEniIp,
		TargetMin:       targetMin,
		Target:          target,
		MaxCap:          totalMax,
		MaxCapProbe:     *cfg.PoolMaxCapProbe,
		MonitorInterval: time.Duration(*cfg.PoolMonitorIntervalSec) * time.Second,
		GCProtectPeriod: time.Duration(*cfg.PoolGCProtectPeriodSec) * time.Second,
	}
}

func newEniIPResourceManager(cfg *config.Config, subnet helper.SubnetManager, secManager helper.SecurityGroupManager, volcApi helper.VolcAPI, allocatedResource map[string]types.NetResourceAllocated, k8s k8s.Service) (*eniIPResourceManager, error) {
	log.Infof("Creating EniIPResourceManager")
	limit, err := helper.NewInstanceLimitManager(volcApi)
	if err != nil {
		return nil, err
	}
	m := &eniIPResourceManager{}
	poolConfig := generateIPPoolCfg(cfg, limit.GetLimit())

	_, created, err := volcApi.GetAttachedENIs(false)
	if err != nil {
		return nil, fmt.Errorf("get attached enis failed while init, %v", err)
	}

	eniFact, err := newEniFactory(secManager, subnet, volcApi, limit, types.IPFamily(*cfg.IPFamily))
	if err != nil {
		return nil, fmt.Errorf("create eni factory failed, %v", err)
	}

	// trunk
	m.trunkEni = limit.GetLimit().TrunkENI
	if *cfg.EnableTrunk && m.trunkEni == nil {
		res, err := eniFact.CreateWithIPCount(1, true)
		if err != nil {
			return nil, fmt.Errorf("alloc trunk eni failed, %v", err)
		}
		m.trunkEni = res.(*types.ENI)
	}

	factory := &eniIPFactory{
		eniFactory:    eniFact,
		RWMutex:       sync.RWMutex{},
		enis:          []*ENI{},
		volcApi:       volcApi,
		eniIpReceiver: make(chan *ENIIPRes, defaultOrderCnt),
		eniPending:    make(chan struct{}, defaultEniPending),
		ipFamily:      types.IPFamily(*cfg.IPFamily),
	}
	poolConfig.Factory = factory
	poolConfig.PreStart = func(pool pool.ResourcePoolOp) error {
		// init factory and pool
		for _, eni := range created {
			v4s, v6s, inErr := volcApi.GetENIIPList(eni.Mac.String())
			if inErr != nil {
				return fmt.Errorf("get ip list on eni %s failed, %v", eni.Mac.String(), inErr)
			}
			fEni := &ENI{
				Mutex:      sync.Mutex{},
				ENI:        eni,
				ips:        []*ENIIPRes{},
				order:      make(chan struct{}, defaultOrderCnt),
				stopWorker: make(chan struct{}, 1),
				volcApi:    volcApi,
			}
			factory.appendEniLocked(fEni)

			v4sMap := ip.NetIPToMap(v4s)
			v6sMap := ip.NetIPToMap(v6s)
			for _, item := range allocatedResource {
				if item.Resource.GetVPCResource().ENIId != eni.ID {
					continue
				}
				ipSet := types.IPSet{
					IPv4: net.ParseIP(item.Resource.GetVPCResource().IPv4),
					IPv6: net.ParseIP(item.Resource.GetVPCResource().IPv6),
				}
				eniIP := &types.ENIIP{
					ENI:   eni,
					IPSet: ipSet,
				}
				pool.AddInuse(eniIP, item.Owner)
				if ipSet.IPv4 != nil {
					delete(v4sMap, ipSet.IPv4.String())
				}
				if ipSet.IPv6 != nil {
					delete(v6sMap, ipSet.IPv6.String())
				}

				if !factory.ipFamily.EnableIPv4() {
					ipSet.IPv4 = nil
				}
				if !factory.ipFamily.EnableIPv6() {
					ipSet.IPv6 = nil
				}
				var resErr error
				if (factory.ipFamily.EnableIPv4() && ipSet.IPv4 == nil) ||
					(factory.ipFamily.EnableIPv6() && ipSet.IPv6 == nil) {
					resErr = ErrLegacy
				}
				fEni.appendIPLocked(&ENIIPRes{
					ENIIP: &types.ENIIP{
						ENI:   eni,
						IPSet: ipSet,
					},
					err: resErr,
				})
			}

			if factory.ipFamily.EnableIPv4() && !factory.ipFamily.EnableIPv6() {
				for _, ipv4 := range v4sMap {
					eniIP := &ENIIPRes{
						ENIIP: &types.ENIIP{
							ENI: eni,
							IPSet: types.IPSet{
								IPv4: ipv4,
							},
						},
					}
					fEni.appendIPLocked(eniIP)
					pool.AddAvailable(eniIP.ENIIP) // no need to deal with ipv6
				}
			} else if !factory.ipFamily.EnableIPv4() && factory.ipFamily.EnableIPv6() {
				for _, ipv6 := range v6sMap {
					eniIP := &ENIIPRes{
						ENIIP: &types.ENIIP{
							ENI: eni,
							IPSet: types.IPSet{
								IPv6: ipv6,
							},
						},
					}
					fEni.appendIPLocked(eniIP)
					pool.AddAvailable(eniIP.ENIIP) // no need to deal with ipv4
				}
			} else {
				// pair last
				var v4List, v6List []net.IP
				for _, v4 := range v4sMap {
					v4List = append(v4List, v4)
				}
				for _, v6 := range v6sMap {
					v6List = append(v6List, v6)
				}
				for _, ipSet := range types.PairIPs(v4List, v6List) {
					eniIP := &ENIIPRes{
						ENIIP: &types.ENIIP{
							ENI:   eni,
							IPSet: ipSet,
						},
					}
					fEni.appendIPLocked(eniIP)
					if ipSet.IPv4 == nil || ipSet.IPv6 == nil {
						pool.AddInvalid(eniIP.ENIIP)
					} else {
						pool.AddAvailable(eniIP.ENIIP)
					}
				}
			}
			go fEni.worker(factory.eniIpReceiver)
		}
		return nil
	}
	go factory.subnetMonitor(time.Duration(*cfg.SubnetStatUpdateIntervalSec)*time.Second,
		time.Duration(*cfg.SubnetStatAgingSec)*time.Second)
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

type ENIIPRes struct {
	*types.ENIIP
	err error
}

// ENI is ENI holder in eni factory.
type ENI struct {
	sync.Mutex
	*types.ENI
	ips          []*ENIIPRes
	pending      int
	order        chan struct{}
	stopWorker   chan struct{}
	volcApi      helper.VolcAPI
	forbidAssign bool
}

func (e *ENI) appendIPLocked(ip *ENIIPRes) {
	for _, old := range e.ips {
		if old.GetID() == ip.GetID() {
			return
		}
	}
	ip.ENI = e.ENI
	e.ips = append(e.ips, ip)
}

func (e *ENI) deleteIPLocked(ip *types.ENIIP) {
	for i, item := range e.ips {
		if item.GetID() == ip.GetID() {
			e.ips[len(e.ips)-1], e.ips[i] = e.ips[i], e.ips[len(e.ips)-1]
			e.ips = e.ips[:len(e.ips)-1]
			break
		}
	}
}

func (e *ENI) getCurrentIPCountLocked() int {
	return len(e.ips) + e.pending
}

func (e *ENI) submitOrderLocked() error {
	select {
	case e.order <- struct{}{}:
	default:
		return fmt.Errorf("order overflow")
	}
	return nil
}

func (e *ENI) worker(resultCache chan<- *ENIIPRes) {
	for {
		toAssign := 0
		select {
		case <-e.stopWorker:
			return
		case <-e.order: // process order
			toAssign += 1
		}
		time.Sleep(500 * time.Millisecond)
	processOrder:
		for {
			select {
			case <-e.order:
				toAssign++
			default:
				break processOrder
			}
		}

		log.Debugf("Begin assign %d ips on eni %s", toAssign, e.ID)
		v4, v6, err := e.volcApi.AllocIPAddresses(e.ID, e.Mac.String(), toAssign, toAssign)
		if err != nil {
			log.Errorf("Assign ip failed on eni %s, %v", e.ID, err)
			for i := 0; i < toAssign; i++ {
				resultCache <- &ENIIPRes{
					ENIIP: &types.ENIIP{
						ENI: e.ENI,
					},
					err: err,
				}
			}
			if strings.Contains(err.Error(), apiErr.InsufficientIpInSubnet) {
				e.Lock()
				e.forbidAssign = true
				e.Unlock()
			}
		} else {
			for _, ipSet := range types.PairIPs(v4, v6) {
				resultCache <- &ENIIPRes{
					ENIIP: &types.ENIIP{
						ENI:   e.ENI,
						IPSet: ipSet,
					},
				}
			}
		}
	}
}

// eniIPFactory is used to manage ENI IP resource.
type eniIPFactory struct {
	eniFactory *eniFactory
	sync.RWMutex
	enis          []*ENI
	volcApi       helper.VolcAPI
	eniIpReceiver chan *ENIIPRes
	eniPending    chan struct{}
	ipFamily      types.IPFamily
}

func (f *eniIPFactory) Name() string {
	return types.NetResourceTypeEniIp
}

// receiveRes receives new created ENIIP.
func (f *eniIPFactory) receiveRes() (ip *types.ENIIP, err error) {
	eniIP := <-f.eniIpReceiver
	resErr := eniIP.err
	if resErr != nil && (strings.Contains(resErr.Error(), apiErr.LimitExceededPrivateIpsPerEni) ||
		strings.Contains(resErr.Error(), apiErr.LimitExceededIpv6AddressesPerEni)) {
		f.eniFactory.limit.Update()
		signal.NotifySignal(signal.WakeGC, signal.SigWakeGC)
	}

	if eniIP.ENIIP == nil || resErr != nil {
		f.Lock()
		defer f.Unlock()
		if eniIP.ENI != nil {
			for _, eni := range f.enis {
				if eni.ENI == nil {
					continue
				}
				if eni.ID == eniIP.ENI.ID {
					eni.pending--
				}
			}
		}
		return nil, fmt.Errorf("ip allocated failed, %v", eniIP.err)
	}

	f.Lock()
	defer f.Unlock()
	for _, eni := range f.enis {
		if eni.ENI != nil && eni.ID == eniIP.ENI.ID {
			eni.Lock()
			eni.appendIPLocked(eniIP)
			eni.pending--
			eni.Unlock()
			return eniIP.ENIIP, nil
		}
	}
	return nil, fmt.Errorf("expected resource not return, %s", render.Render(eniIP))
}

// submitOrder submits order to create ENIIP.
func (f *eniIPFactory) submitOrder() error {
	f.Lock()
	defer f.Unlock()

	for _, eni := range f.enis {
		if eni.ENI == nil {
			log.Debugf("Skip initializing eni")
			continue
		}
		eni.Lock()
		subnet := f.eniFactory.subnets.GetPodSubnet(eni.Subnet.ID)
		subnetIPFamily := subnet.IPFamily()
		if !subnetIPFamily.Support(f.ipFamily) {
			log.Warnf("Skip submit order to eni %s because subnet ipFamily %s not support %s", eni.ID, subnetIPFamily, f.ipFamily)
			eni.forbidAssign = true
			eni.Unlock()
			continue
		}
		if eni.forbidAssign {
			log.Debugf("Skip submit order to eni %v because forbidAssign", eni.GetID())
			eni.Unlock()
			continue
		}

		if eni.getCurrentIPCountLocked() < f.getLimit().IPv4MaxPerENI {
			if err := eni.submitOrderLocked(); err != nil {
				log.Warnf("Submit order failed, %v", err)
				eni.Unlock()
				continue
			}
			eni.pending++
			eni.Unlock()
			return nil
		}
		eni.Unlock()
	}
	return fmt.Errorf("cant process order")
}

func (f *eniIPFactory) appendEniLocked(eni *ENI) *ENI {
	for _, old := range f.enis {
		id := old.GetID()
		if id != "" && id == eni.GetID() {
			return old
		}
	}
	f.enis = append(f.enis, eni)
	return eni
}

func (f *eniIPFactory) deleteEniLocked(eni *ENI) {
	if eni == nil {
		return
	}
	for i, item := range f.enis {
		if item == eni {
			f.enis[len(f.enis)-1], f.enis[i] = f.enis[i], f.enis[len(f.enis)-1]
			f.enis = f.enis[:len(f.enis)-1]
			break
		}
	}
}

// initENI initializes ENI.
func (f *eniIPFactory) initENI(eni *ENI) {
	var err error
	var ipv4s, ipv6s []net.IP

	defer func() {
		<-f.eniPending
	}()

	vpcEni, err := f.eniFactory.CreateWithIPCount(eni.pending, false)
	if err == nil {
		var ok bool
		eni.ENI, ok = vpcEni.(*types.ENI)
		if !ok {
			log.Errorf("Net resource created by factory is not expect type eni, try release it")
			err = f.eniFactory.Release(vpcEni)
			if err != nil {
				log.Errorf("Release unexpect resource %+v failed, %v", vpcEni, err)
			}
		} else {
			ipv4s, ipv6s, err = f.volcApi.GetENIIPList(eni.Mac.String())
			if err != nil {
				log.Errorf("Get ip list on eni failed, %v, try release it", err)
				err = f.eniFactory.Release(vpcEni)
				if err != nil {
					log.Errorf("Release eni %+v failed, %v", vpcEni, err)
				}
			}
			if f.ipFamily.EnableIPv4() && f.ipFamily.EnableIPv6() {
				// check ip pairs
				if len(ipv4s) != len(ipv6s) {
					log.Errorf("The number of ipv4 and ipv6 not equal on eni %+v, try release it", vpcEni)
					err = f.eniFactory.Release(vpcEni)
					if err != nil {
						log.Errorf("Release eni %+v failed, %v", vpcEni, err)
					}
				}
			}
		}
	}

	if err != nil {
		// clean
		eni.Lock()
		for i := 0; i < eni.pending; i++ {
			f.eniIpReceiver <- &ENIIPRes{
				ENIIP: &types.ENIIP{
					ENI: nil,
				},
				err: fmt.Errorf("init eni failed, %v", err),
			}
		}
		eni.forbidAssign = true
		eni.pending = 0
		eni.Unlock()

		f.Lock()
		f.deleteEniLocked(eni)
		f.Unlock()
		return
	}

	// pair result
	eni.Lock()
	for _, ipSet := range types.PairIPs(ipv4s, ipv6s) {
		f.eniIpReceiver <- &ENIIPRes{
			ENIIP: &types.ENIIP{
				ENI:   eni.ENI,
				IPSet: ipSet,
			},
			err: nil,
		}
	}

	eni.Unlock()
	go eni.worker(f.eniIpReceiver)
}

// createEniAsync creates ENI asynchronously.
func (f *eniIPFactory) createEniAsync(withIPs int) (*ENI, error) {
	eni := &ENI{
		Mutex:        sync.Mutex{},
		ENI:          nil,
		ips:          make([]*ENIIPRes, 0),
		pending:      withIPs,
		order:        make(chan struct{}, defaultOrderCnt),
		stopWorker:   make(chan struct{}, 1),
		volcApi:      f.volcApi,
		forbidAssign: false,
	}

	f.Lock()
	defer f.Unlock()
	limit := f.getLimit().ENIAvailable()
	if len(f.enis) < limit {
		select {
		case f.eniPending <- struct{}{}:
		default:
			return nil, fmt.Errorf("the number of eni processed at the same time has reached the upper limit %d", defaultEniPending)
		}
		f.appendEniLocked(eni)
		go f.initENI(eni)
	} else {
		return nil, fmt.Errorf("the number of eni that can be created in this instance has reached the upper limit, limit: %d, current: %d", limit, len(f.enis))
	}
	return eni, nil
}

// Create creates NetResources using given count.
func (f *eniIPFactory) Create(count int) ([]types.NetResource, error) {
	var err error
	var allocatedIP []types.NetResource
	submitted := 0

	for ; submitted < count; submitted++ {
		err = f.submitOrder()
		if err != nil {
			break
		}
	}

	lackIP := count - submitted
	lackIP = math.Min(lackIP, f.getLimit().IPv4MaxPerENI)
	lackIP = math.Min(lackIP, defaultOrderCnt)

	if lackIP > 0 {
		_, err = f.createEniAsync(lackIP)
		if err != nil {
			log.Errorf("Create eni async failed, %v", err)
		} else {
			submitted += lackIP
		}
	}

	if submitted == 0 {
		return allocatedIP, fmt.Errorf("submit resource order failed, %v", err)
	}

	var eniIP *types.ENIIP
	for ; submitted > 0; submitted-- { // receive allocate result
		eniIP, err = f.receiveRes()
		if err != nil {
			log.Errorf("Receive allocated ip address failed, %+v", err)
		} else {
			allocatedIP = append(allocatedIP, eniIP)
		}
	}

	if len(allocatedIP) == 0 {
		return nil, fmt.Errorf("receive allocated ip address failed, %+v", err)
	}
	return allocatedIP, nil
}

// ReleaseInValid releases invalid NetResource.
func (f *eniIPFactory) ReleaseInValid(resource types.NetResource) (types.NetResource, error) {
	res, ok := resource.(*types.ENIIP)
	if !ok {
		return nil, fmt.Errorf("type of resource is not %s", types.NetResourceTypeEniIp)
	}
	if res.ENI == nil {
		return nil, fmt.Errorf("eni of resource is nil")
	}

	var temp *ENI
	eni := res.ENI
	ipSet := res.IPSet

	if eni.Trunk {
		return nil, fmt.Errorf("eni is trunk, operation invalid")
	}

	f.RLock()
	for _, e := range f.enis {
		if e.ENI == nil {
			continue
		}
		if e.ID == res.ENI.ID {
			temp = e
			break
		}
	}
	f.RUnlock()

	if temp == nil {
		log.Warnf("ENI %v not exist in this instance", eni)
		return nil, nil
	}

	if ipSet.GetIPv4() == "" || !eni.PrimaryIP.IPv4.Equal(ipSet.IPv4) { // release
		var v4s, v6s []net.IP
		if ipSet.IPv4 != nil {
			v4s = append(v4s, ipSet.IPv4)
		}
		if ipSet.IPv6 != nil {
			v6s = append(v6s, ipSet.IPv6)
		}

		err := f.volcApi.DeallocIPAddresses(eni.ID, eni.Mac.String(), v4s, v6s)
		if err != nil {
			return nil, fmt.Errorf("dealloc ip address failed, %v", err)
		}
		temp.Lock()
		temp.deleteIPLocked(res)
		temp.Unlock()
		return nil, nil
	}

	// Process with primary IP.
	{
		if ipSet.IPv6 != nil {
			err := f.volcApi.DeallocIPAddresses(eni.ID, eni.Mac.String(), nil, []net.IP{ipSet.IPv6})
			if err != nil {
				return nil, fmt.Errorf("dealloc ipaddress failed, %v", err)
			}
			temp.Lock()
			temp.deleteIPLocked(res)
			temp.Unlock()
		}

		if !f.ipFamily.EnableIPv4() && f.ipFamily.EnableIPv6() { // v6 only
			return nil, nil
		}

		var newV6 net.IP
		if f.ipFamily.EnableIPv6() { // dual
			// pair with ipv6
			_, v6s, err := f.volcApi.AllocIPAddresses(temp.ID, temp.Mac.String(), 0, 1)
			if err != nil || len(v6s) != 1 {
				return nil, fmt.Errorf("alloc ipv6 address failed while pair with primary ipv4, %v", err)
			}
			newV6 = v6s[0]
		}

		newEniIP := &types.ENIIP{
			ENI: temp.ENI,
			IPSet: types.IPSet{
				IPv4: ipSet.IPv4,
				IPv6: newV6,
			},
		}
		f.Lock()
		temp.Lock()
		temp.appendIPLocked(&ENIIPRes{
			ENIIP: newEniIP,
		})
		temp.Unlock()
		f.Unlock()
		return newEniIP, nil
	}
}

// Release releases NetResource.
func (f *eniIPFactory) Release(resource types.NetResource) error {
	// check
	res, ok := resource.(*types.ENIIP)
	if !ok {
		return fmt.Errorf("type of resource is not %s", types.NetResourceTypeEniIp)
	}
	if res.ENI == nil {
		return fmt.Errorf("eni of resource is nil")
	}
	var eni *ENI
	var eniIP *types.ENIIP

	f.RLock()
outLoop:
	for _, e := range f.enis {
		if e.ENI == nil {
			continue
		}
		if e.ID == res.ENI.ID {
			eni = e
			e.Lock()
			for _, ipRes := range e.ips {
				if ipRes.IPSet.String() == res.IPSet.String() {
					eniIP = ipRes.ENIIP
					e.Unlock()
					break outLoop
				}
			}
			e.Unlock()
		}
	}
	f.RUnlock()

	if eni == nil || eniIP == nil {
		return apiErr.ErrNotFound
	}

	if eni.Trunk {
		return fmt.Errorf("eni is trunk, operation invalid")
	}

	// check eni should release
	eni.Lock()
	if len(eni.ips) == 1 { // primary ip or pair with primary ip
		if eni.pending > 0 {
			eni.Unlock()
			return fmt.Errorf("allocate action on eni %s", eni.ID)
		}
		f.eniPending <- struct{}{}
		eni.forbidAssign = true
		eni.Unlock()

		f.Lock()
		close(eni.stopWorker)
		f.deleteEniLocked(eni)
		f.Unlock()

		err := f.eniFactory.Release(eni)
		<-f.eniPending
		if err != nil {
			return fmt.Errorf("release ENI for eniip failed, %v", err)
		}
		return nil
	}
	eni.Unlock()

	if res.ENI.PrimaryIP.IPv4.Equal(res.IPSet.IPv4) {
		return apiErr.ErrInvalidDeletionPrimaryIP
	}

	// release ip
	var v4s, v6s []net.IP
	if res.IPSet.IPv4 != nil {
		v4s = append(v4s, res.IPSet.IPv4)
	}
	if res.IPSet.IPv6 != nil {
		v6s = append(v6s, res.IPSet.IPv6)
	}

	err := f.volcApi.DeallocIPAddresses(res.ENI.ID, res.ENI.Mac.String(), v4s, v6s)
	if err != nil && !strings.Contains(err.Error(), apiErr.ErrHalfwayFailed.Error()) {
		return fmt.Errorf("dealloc ipaddress failed, %v", err)
	}
	eni.Lock()
	eni.deleteIPLocked(eniIP)
	eni.Unlock()
	return nil
}

// Valid checks if given NetResource is valid.
func (f *eniIPFactory) Valid(resource types.NetResource) error {
	eniIP, ok := resource.(*types.ENIIP)
	if !ok {
		return fmt.Errorf("type of resource is not %s", types.NetResourceTypeEniIp)
	}
	if eniIP.ENI == nil {
		return fmt.Errorf("eni of resource is nil")
	}
	f.RLock()
	defer f.RUnlock()
	var find *ENIIPRes
	for _, eni := range f.enis {
		if eni.ENI == nil {
			continue
		}
		if eni.ID == eniIP.ENI.ID {
			eni.Lock()
			for _, addr := range eni.ips {
				if addr.IPSet.String() == eniIP.IPSet.String() {
					find = addr
					break
				}
			}
			eni.Unlock()
			if find != nil {
				break
			}
		}
	}

	if find != nil {
		return find.err
	}

	return apiErr.ErrNotFound
}

// List return list of normal、legacy、invalid resource
func (f *eniIPFactory) List() (map[types.ResStatus]map[string]types.NetResource, error) {
	f.RLock()
	defer f.RUnlock()

	list := map[types.ResStatus]map[string]types.NetResource{}
	list[types.ResStatusNormal] = map[string]types.NetResource{}
	list[types.ResStatusLegacy] = map[string]types.NetResource{}
	list[types.ResStatusInvalid] = map[string]types.NetResource{}

	eniMacs, err := f.volcApi.GetSecondaryENIMACs()
	if err != nil {
		return nil, fmt.Errorf("get eni macs failed, %v", err)
	}

	eniIpMap := map[string]struct {
		v4Map map[string]net.IP
		v6Map map[string]net.IP
	}{}
	for _, mac := range eniMacs {
		v4s, v6s, err := f.volcApi.GetENIIPList(mac)
		if err != nil {
			return nil, fmt.Errorf("get ip list for %s failed, %v", mac, err)
		}
		eniIpMap[mac] = struct {
			v4Map map[string]net.IP
			v6Map map[string]net.IP
		}{v4Map: ip.NetIPToMap(v4s), v6Map: ip.NetIPToMap(v6s)}
	}

	for _, eni := range f.enis {
		if eni.ENI == nil {
			continue
		}
		ipMap, exist := eniIpMap[eni.Mac.String()]
		if !exist {
			ipMap = struct {
				v4Map map[string]net.IP
				v6Map map[string]net.IP
			}{v4Map: map[string]net.IP{}, v6Map: map[string]net.IP{}}
		}
		eni.Lock()
		for _, eniipRes := range eni.ips {
			valid := true
			if eniipRes.IPSet.IPv4 != nil {
				if _, ok := ipMap.v4Map[eniipRes.IPSet.IPv4.String()]; !ok {
					valid = false
				}
			}
			if eniipRes.IPSet.IPv6 != nil {
				if _, ok := ipMap.v6Map[eniipRes.IPSet.IPv6.String()]; !ok {
					valid = false
				}
			}
			item := &types.ENIIP{
				ENI:   eniipRes.ENI,
				IPSet: eniipRes.IPSet,
			}
			if !valid {
				list[types.ResStatusInvalid][item.GetID()] = item
			} else if eniipRes.err == nil {
				list[types.ResStatusNormal][item.GetID()] = item
			} else if errors.Is(eniipRes.err, ErrLegacy) {
				list[types.ResStatusLegacy][item.GetID()] = item
			} else {
				list[types.ResStatusInvalid][item.GetID()] = item
			}
		}
		eni.Unlock()
	}
	return list, nil
}

func (f *eniIPFactory) subnetMonitor(updateInterval, aging time.Duration) {
	go wait.JitterUntil(func() {
		err := f.eniFactory.subnets.UpdateSubnetsStatus(helper.WithAging(aging))
		if err != nil {
			log.Errorf("SubnetMonitor reconcile failed, %v", err)
			return
		}
		f.Lock()
		for _, eni := range f.enis {
			// Skip uninitialized ENI.
			if eni.ENI == nil {
				continue
			}
			subnet := f.eniFactory.subnets.GetPodSubnet(eni.Subnet.ID)
			if subnet == nil {
				log.Errorf("Get subnet %s from subnetManager failed, not found")
				continue
			}
			if subnet.IPFamily().Support(f.ipFamily) && subnet.GetAvailableIpAddressCount() > 0 {
				eni.forbidAssign = false
			}
		}
		f.Unlock()
	}, updateInterval, 0.2, true, wait.NeverStop)
}

func (f *eniIPFactory) getLimit() *helper.InstanceLimits {
	limit := f.eniFactory.limit.GetLimit()
	return &limit
}

func (f *eniIPFactory) GetResourceLimit() int {
	f.Lock()
	defer f.Unlock()

	limit := f.getLimit()
	nick := 0

	for _, eni := range f.enis {
		eni.Lock()
		if eni.forbidAssign {
			nick += limit.IPv4MaxPerENI - eni.getCurrentIPCountLocked()
		}
		eni.Unlock()
	}
	return limit.ENIAvailable()*limit.IPv4MaxPerENI - nick
}

func (f *eniIPFactory) GC() error {
	f.Lock()
	defer f.Unlock()
	if len(f.eniPending) > 0 {
		log.Infof("Skip gc for eniIPFactory due to eni pending")
		return nil
	}

	log.Debugf("Start gc for eniIPFactory")
	ipKey := func(eniId, ip string) string {
		return fmt.Sprintf("%s/%s", eniId, ip)
	}

	eniMap := map[string]*struct { // key is eni-id
		skip bool
		*types.ENI
		v4s []net.IP
		v6s []net.IP
	}{}
	ipMap := map[string]*struct { // key is eni-id/ip
		used  bool
		eniId string
		ip    types.IPSet
	}{}
	_, enis, err := f.volcApi.GetAttachedENIs(false)
	if err != nil {
		return fmt.Errorf("get attachedENI failed, %v", err)
	}
	if len(enis) == 0 {
		return fmt.Errorf("pass gc due to the number of eni is 0")
	}

	for _, eni := range enis {
		v4s, v6s, err := f.volcApi.GetENIIPList(eni.Mac.String())
		if err != nil {
			return fmt.Errorf("get ip list for %s failed, %v", eni.ID, err)
		}
		eniMap[eni.ID] = &struct {
			skip bool
			*types.ENI
			v4s []net.IP
			v6s []net.IP
		}{ENI: eni}

		for _, v4 := range v4s {
			ipMap[ipKey(eni.ID, v4.String())] = &struct {
				used  bool
				eniId string
				ip    types.IPSet
			}{
				eniId: eni.ID,
				ip: types.IPSet{
					IPv4: v4,
				},
			}
		}
		for _, v6 := range v6s {
			ipMap[ipKey(eni.ID, v6.String())] = &struct {
				used  bool
				eniId string
				ip    types.IPSet
			}{
				eniId: eni.ID,
				ip: types.IPSet{
					IPv6: v6,
				},
			}
		}
	}

	if len(ipMap) == 0 {
		return fmt.Errorf("pass gc due to the number of ip is 0")
	}

	// check stock
	for _, fEni := range f.enis {
		if fEni.ENI == nil {
			continue
		}
		if eni, exist := eniMap[fEni.ID]; exist && fEni.pending != 0 {
			eni.skip = true
			continue
		}

		fEni.Lock()
		for _, fIp := range fEni.ips {
			if fIp.IPSet.IPv4 != nil {
				if o, exist := ipMap[ipKey(fIp.ENI.ID, fIp.IPSet.GetIPv4())]; !exist {
					fIp.err = apiErr.ErrNotFound
				} else {
					o.used = true
				}
			}
			if fIp.IPSet.IPv6 != nil {
				if o, exist := ipMap[ipKey(fIp.ENI.ID, fIp.IPSet.GetIPv6())]; !exist {
					fIp.err = apiErr.ErrNotFound
				} else {
					o.used = true
				}
			}
		}
		fEni.Unlock()
	}

	for _, o := range ipMap {
		if !o.used {
			if o.ip.IPv4 != nil {
				e := eniMap[o.eniId]
				e.v4s = append(e.v4s, o.ip.IPv4)
			}
			if o.ip.IPv6 != nil {
				e := eniMap[o.eniId]
				e.v6s = append(e.v6s, o.ip.IPv6)
			}
		}
	}

	// process not appear
	for _, item := range eniMap {
		if item.skip {
			continue
		}
		temp := &ENI{
			Mutex:      sync.Mutex{},
			ENI:        item.ENI,
			ips:        []*ENIIPRes{},
			order:      make(chan struct{}, defaultOrderCnt),
			stopWorker: make(chan struct{}, 1),
			volcApi:    f.volcApi,
		}
		fEni := f.appendEniLocked(temp)
		fEni.Lock()
		switch f.ipFamily {
		case types.IPFamilyIPv4:
			for _, v4 := range item.v4s {
				fEni.appendIPLocked(&ENIIPRes{
					ENIIP: &types.ENIIP{
						ENI: item.ENI,
						IPSet: types.IPSet{
							IPv4: v4,
						},
					},
				})
			}
		case types.IPFamilyIPv6:
			for _, v6 := range item.v6s {
				fEni.appendIPLocked(&ENIIPRes{
					ENIIP: &types.ENIIP{
						ENI: item.ENI,
						IPSet: types.IPSet{
							IPv6: v6,
						},
					},
				})
			}
		case types.IPFamilyDual:
			pairCnt := math.Min(len(item.v4s), len(item.v6s))
			pairs := types.PairIPs(item.v4s, item.v6s)
			for i := 0; i < pairCnt; i++ {
				fEni.appendIPLocked(&ENIIPRes{
					ENIIP: &types.ENIIP{
						ENI:   item.ENI,
						IPSet: pairs[i],
					},
				})
			}
			v4s := item.v4s[pairCnt:]
			v6s := item.v6s[pairCnt:]
			err = f.volcApi.DeallocIPAddresses(item.ID, item.Mac.String(), v4s, v6s)
			if err != nil {
				log.Errorf("Dealloc extra ip addresses:{%v, %v} failed, %v", v4s, v6s, err)
			}
		}
		if fEni == temp {
			go fEni.worker(f.eniIpReceiver)
		}
		fEni.Unlock()
	}
	return nil
}
