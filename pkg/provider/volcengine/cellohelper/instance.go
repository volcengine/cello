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

package cellohelper

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/types"
)

// InstanceLimitsAttr contains the basic quota and limit information of ecs instance used by cello.
type InstanceLimitsAttr struct {
	ENITotal       int
	ENIQuota       int
	IPv4MaxPerENI  int
	IPv6MaxPerENI  int
	TrunkSupported bool
}

// InstanceLimits quota and limit.
type InstanceLimits struct {
	InstanceLimitsAttr
	ENICustomer int
	// currently support only one
	TrunkENI *types.ENI
}

func (l *InstanceLimits) String() string {
	return fmt.Sprintf("{ENITotal: %d, ENIQuota: %d, IPv4MaxPerENI: %d, IPv6MaxPerENI: %d, TrunkSupported: %t, ENICustomer: %d}",
		l.ENITotal, l.ENIQuota, l.IPv4MaxPerENI, l.IPv6MaxPerENI, l.TrunkSupported, l.ENICustomer)
}

// SupportTrunk support trunk or not.
func (l *InstanceLimits) SupportTrunk() bool {
	return l.TrunkSupported
}

// NonPrimaryENI return the number of eni except primary eni.
func (l *InstanceLimits) NonPrimaryENI() int {
	return l.ENIQuota - 1
}

type InstanceLimitManager interface {
	// GetLimit get InstanceLimits of ecs instance
	GetLimit() InstanceLimits
	// Update update InstanceLimits of ecs instance
	Update()
	// UpdateTrunk update trunk eni to InstanceLimits
	UpdateTrunk(trunk *types.ENI)
}

// ENIAvailable get quota minus the custom eni and primary eni.
func (l *InstanceLimits) ENIAvailable() int {
	cnt := l.ENIQuota - 1 - l.ENICustomer
	if l.TrunkENI != nil {
		cnt -= 1
	}
	return cnt
}

func (l *InstanceLimits) BranchENI() int {
	return l.ENITotal - l.ENIQuota
}

type defaultInstanceLimit struct {
	lock       sync.RWMutex
	api        VolcAPI
	limit      InstanceLimits
	lastUpdate time.Time
}

var instanceLimitManager *defaultInstanceLimit

func (m *defaultInstanceLimit) GetLimit() InstanceLimits {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.limit
}

func (m *defaultInstanceLimit) Update() {
	if err := m.update(); err != nil {
		log.Errorf("Update InstanceLimit failed, %v", err)
	}
}

func (m *defaultInstanceLimit) UpdateTrunk(trunk *types.ENI) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if trunk != nil {
		log.Infof("Update trunk to %s", trunk.ID)
	} else {
		log.Infof("Update trunk to nil")
	}
	m.limit.TrunkENI = trunk
}

func (m *defaultInstanceLimit) update() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if time.Since(m.lastUpdate) < time.Minute {
		return nil
	}
	log.Infof("InstanceLimit Updating")
	limit, err := m.api.GetInstanceLimit()
	if err != nil {
		return err
	}

	oldLimit := m.limit.InstanceLimitsAttr
	emptyLimit := InstanceLimitsAttr{}
	if oldLimit != emptyLimit && oldLimit != limit.InstanceLimitsAttr {
		_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventInstanceQuotaUpdated,
			fmt.Sprintf("ECS instance quota updated from %v to %v", oldLimit, *limit))
	}

	created, err := m.api.GetAttachedENIs(true)
	if err != nil {
		return err
	}
	total, err := m.api.GetTotalAttachedEniCnt()
	if err != nil {
		return err
	}
	limit.ENICustomer = total - len(created) - 1 // contains primary eni
	for _, e := range created {
		if e.Trunk {
			limit.TrunkENI = e
			break
		}
	}

	log.Infof("InstanceLimit Updated %v", limit)
	m.limit = *limit
	m.lastUpdate = time.Now()
	return nil
}

func NewInstanceLimitManager(api VolcAPI) (InstanceLimitManager, error) {
	if instanceLimitManager != nil {
		return instanceLimitManager, nil
	}

	instanceLimitManager = &defaultInstanceLimit{
		lock: sync.RWMutex{},
		api:  api,
	}
	if err := instanceLimitManager.update(); err != nil {
		return nil, err
	}
	return instanceLimitManager, nil
}

var defaultInstanceMetadata *InstanceMetadata
var once sync.Once

type InstanceMetadataGetter interface {
	GetVpcId() string
	GetInstanceId() string
	GetInstanceType() string
	GetPrimaryENIId() string
	GetPrimaryENIMac() string
	GetAvailabilityZone() string
	GetRegion() string
}

type InstanceMetadata struct {
	VpcId            string
	InstanceId       string
	InstanceType     string
	PrimaryENIId     string
	PrimaryENIMac    string
	AvailabilityZone string
	Region           string
}

func (m *InstanceMetadata) GetVpcId() string {
	return m.VpcId
}

func (m *InstanceMetadata) GetInstanceId() string {
	return m.InstanceId
}

func (m *InstanceMetadata) GetInstanceType() string {
	return m.InstanceType
}

func (m *InstanceMetadata) GetPrimaryENIId() string {
	return m.PrimaryENIId
}

func (m *InstanceMetadata) GetPrimaryENIMac() string {
	return m.PrimaryENIMac
}

func (m *InstanceMetadata) GetAvailabilityZone() string {
	return m.AvailabilityZone
}

func (m *InstanceMetadata) GetRegion() string {
	return m.Region
}

// GetInstanceMetadata return basic information of ecs instance, only obtain once.
func GetInstanceMetadata() InstanceMetadataGetter {
	once.Do(func() {
		ctx := context.Background()
		meta := metadata.NewEC2MetadataWrapper(metadata.New())
		vpcId, err := meta.GetVpcId(ctx)
		if err != nil {
			panic(fmt.Errorf("get vpcId for instance failed, %v", err))
		}
		instanceId, err := meta.GetInstanceID(ctx)
		if err != nil {
			panic(fmt.Errorf("get instanceId for instance failed, %v", err))
		}
		instanceType, err := meta.GetInstanceType(ctx)
		if err != nil {
			panic(fmt.Errorf("get instanceType for instance failed, %v", err))
		}
		primaryENIMac, err := meta.GetPrimaryENIMac(ctx)
		if err != nil {
			panic(fmt.Errorf("get primaryENIMac for instance failed, %v", err))
		}
		primaryENIId, err := meta.GetENIID(ctx, primaryENIMac)
		if err != nil {
			panic(fmt.Errorf("get primaryENIId for instance failed, %v", err))
		}
		az, err := meta.GetAvailabilityZone(ctx)
		if err != nil {
			panic(fmt.Errorf("get az for instance failed, %v", err))
		}
		region, err := meta.GetRegionID(ctx)
		if err != nil {
			panic(fmt.Errorf("get region for instance failed, %v", err))
		}
		defaultInstanceMetadata = &InstanceMetadata{
			VpcId:            vpcId,
			InstanceId:       instanceId,
			InstanceType:     instanceType,
			PrimaryENIId:     primaryENIId,
			PrimaryENIMac:    primaryENIMac,
			AvailabilityZone: az,
			Region:           region,
		}
	})
	return defaultInstanceMetadata
}
