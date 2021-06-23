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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/uuid"

	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/utils/math"
	"github.com/volcengine/cello/types"
)

const (
	trys                   = 5
	defaultMonitorInterval = 2 * time.Minute
)

type mockObjectFactory struct {
	sync.Mutex
	objects map[string]types.NetResource // id <---> id
	idIndex int
	created int
	backoff time.Duration
	cap     int
}

func (m *mockObjectFactory) Name() string {
	return "mockFactory"
}

func (m *mockObjectFactory) getCreated() int {
	m.Lock()
	defer m.Unlock()
	return m.created
}

func newOwner(i int) string {
	return fmt.Sprintf("pod-%d", i)
}

func newId(i int) string {
	return fmt.Sprintf("ID-%d", i)
}

func (m *mockObjectFactory) newId() string {
	id := newId(m.idIndex)
	m.idIndex++
	return id
}

func (m *mockObjectFactory) preProcess() error {
	time.Sleep(m.backoff)
	return nil
}

func (m *mockObjectFactory) Add(count int) []types.NetResource {
	m.Lock()
	defer m.Unlock()
	var result []types.NetResource
	for i := 0; i < count; i++ {
		resId := m.newId()
		res := &types.MockNetResource{ID: resId}
		m.objects[resId] = res
		result = append(result, res)
	}
	return result
}

func (m *mockObjectFactory) Create(count int) ([]types.NetResource, error) {
	if err := m.preProcess(); err != nil {
		return nil, err
	}
	m.Lock()
	defer m.Unlock()

	var result []types.NetResource
	for i := 0; i < count; i++ {
		if len(m.objects) >= m.cap {
			return result, fmt.Errorf("reach limit")
		}
		resId := m.newId()
		res := &types.MockNetResource{ID: resId}
		m.objects[resId] = res
		m.created++
		result = append(result, res)
	}
	return result, nil
}

func (m *mockObjectFactory) Release(resource types.NetResource) error {
	if err := m.preProcess(); err != nil {
		return err
	}
	if resource == nil {
		return nil
	}
	m.Lock()
	defer m.Unlock()
	delete(m.objects, resource.GetID())
	return nil
}

func (m *mockObjectFactory) ReleaseInValid(resource types.NetResource) (types.NetResource, error) {
	return nil, m.Release(resource)
}

func (m *mockObjectFactory) Valid(resource types.NetResource) error {
	if err := m.preProcess(); err != nil {
		return err
	}
	m.Lock()
	defer m.Unlock()

	if _, exist := m.objects[resource.GetID()]; exist {
		return nil
	}
	return apiErr.ErrNotFound
}

func (m *mockObjectFactory) List() (map[types.ResStatus]map[string]types.NetResource, error) {
	if err := m.preProcess(); err != nil {
		return nil, err
	}
	m.Lock()
	defer m.Unlock()

	list := map[types.ResStatus]map[string]types.NetResource{}
	normal := map[string]types.NetResource{}
	for id, item := range m.objects {
		normal[id] = item
	}
	list[types.ResStatusNormal] = normal
	return list, nil
}

func (m *mockObjectFactory) GC() error {
	return nil
}

func (m *mockObjectFactory) GetResourceLimit() int {
	m.Lock()
	defer m.Unlock()
	return m.cap
}

func (m *mockObjectFactory) setResourceLimit(cap int) {
	m.Lock()
	defer m.Unlock()
	m.cap = cap
}

func newMockObjectFactory(cap int) *mockObjectFactory {
	return &mockObjectFactory{
		objects: make(map[string]types.NetResource),
		backoff: 0 * time.Second,
		cap:     cap,
	}
}

func createPool(factory *mockObjectFactory, target, targetMin, maxCap int, maxCapProbe bool, initInuse, initAvailable, initInvalid int, monitorInterval time.Duration) ResourcePool {
	cfg := Config{
		Name:            "mock-pool",
		Type:            "mock",
		TargetMin:       targetMin,
		Target:          target,
		MaxCap:          maxCap,
		MaxCapProbe:     maxCapProbe,
		MonitorInterval: monitorInterval,
		Factory:         factory,
		PreStart: func(pool ResourcePoolOp) error {
			if initInuse > 0 {
				inUse := factory.Add(initInuse)
				for i, item := range inUse {
					pool.AddInuse(item, newOwner(i))
				}
			}
			if initAvailable > 0 {
				av := factory.Add(initAvailable)
				for _, item := range av {
					pool.AddAvailable(item)
				}
			}

			for i := 0; i < initInvalid; i++ {
				pool.AddInvalid(&types.MockNetResource{ID: string(uuid.NewUUID())})
			}

			return nil
		},
	}
	pool, err := NewResourcePool(cfg)
	if err != nil {
		panic(err)
	}
	return pool
}

func TestCreatePool(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}{
		{3, 5, 20, 0, 0, 0},
		{5, 3, 20, 0, 0, 0},
		{3, 5, 20, 2, 0, 0},
		{3, 5, 20, 2, 21, 0},
		{3, 5, 20, 30, 0, 0},
		{3, 30, 20, 0, 0, 0},
		{30, 5, 20, 0, 0, 0},
		{3, 5, 20, 7, 8, 0},
		{3, 5, 20, 3, 7, 1},
		{0, 5, 20, 0, 0, 0},
		{0, 5, 20, 5, 2, 0},
		{0, 0, 20, 0, 0, 0},
		{0, 0, 20, 5, 0, 0},
		{0, 0, 20, 20, 0, 0},
		{0, 0, 20, 30, 0, 0},
		{0, 0, 20, 5, 3, 5},
		{0, 0, 20, 5, 21, 5},
		{21, 5, 20, 2, 21, 0},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		var inUse, available, invalid int
		// wait pool ready
		for i := 0; i < trys; i++ {
			inUse, available, invalid = 0, 0, 0
			var err error
			var snapShot ResourcePoolSnapshot
			var poolRes, metaRes map[string]types.NetResourceStatus
			snapShot, err = pool.GetSnapshot()
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			poolRes = snapShot.PoolSnapshot()
			metaRes = snapShot.MetaSnapshot()
			for _, item := range poolRes {
				if item.GetStatus() == types.ResStatusInUse {
					inUse++
				}
				if item.GetStatus() == types.ResStatusAvailable {
					available++
				}
				if item.GetStatus() == types.ResStatusInvalid {
					invalid++
				}
			}

			for _, item := range poolRes {
				if _, exist := metaRes[item.GetID()]; !exist {
					time.Sleep(time.Second)
					continue
				}
			}

			if invalid == 0 &&
				inUse == arg.initInuse &&
				available == math.Min(math.Max(arg.maxCap-arg.initInuse, 0), math.Max(arg.target, math.Max(arg.targetMin-arg.initInuse, 0))) {
				return true, nil
			}
			time.Sleep(2 * time.Second)
		}
		return false, fmt.Errorf("actual result: inUse: %d, available: %d, invalid: %d", inUse, available, invalid)
	}

	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %+v not pass, %v", testCase, err))
	}
}

func TestAllocateAny(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}{
		{3, 5, 20, 0, 0, 0, 0},
		{3, 5, 20, 0, 1, 0, 0},
		{3, 5, 20, 0, 0, 0, 2 * time.Second},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		time.Sleep(arg.preWait)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		res, err := pool.Allocate(ctx, "", "pod-mock")
		if err != nil {
			return false, err
		}
		t.Logf("Allocate resource %v", res)
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestAllocatePrefer(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}{
		{3, 5, 20, 0, 5, 0, 2 * time.Second},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		time.Sleep(arg.preWait)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		res, err := pool.Allocate(ctx, "ID-2", "pod-mock")
		if err != nil {
			return false, err
		}
		assert.Equal(t, "ID-2", res.GetID())
		t.Logf("Allocate resource %v", res)
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestAllocatePreferNotExist(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}{
		{3, 5, 20, 0, 5, 0, 2 * time.Second},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		time.Sleep(arg.preWait)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := pool.Allocate(ctx, "ID-6", "pod-mock")
		assert.ErrorIs(t, err, apiErr.ErrNotFound)
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestAllocatePreferInuse(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}{
		{3, 5, 20, 5, 5, 0, 0},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
		preWait       time.Duration
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		time.Sleep(arg.preWait)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		res, err := pool.Allocate(ctx, "ID-2", "pod-2")
		assert.NoError(t, err)
		assert.Equal(t, "ID-2", res.GetID())
		_, err = pool.Allocate(ctx, "ID-2", "pod-3")
		assert.ErrorIs(t, err, apiErr.ErrNotFound)
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestPoolAction(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}{
		{3, 5, 20, 0, 1, 0},
		{3, 5, 20, 5, 1, 0},
		{0, 0, 20, 5, 5, 0},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, 5*time.Second)
		time.Sleep(7 * time.Second)
		snap, err := pool.GetSnapshot()
		assert.NoError(t, err)
		assert.Equal(t, arg.initInuse+math.Max(arg.target, math.Max(arg.targetMin-arg.initInuse, 0)), len(snap.PoolSnapshot()))
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestRelease(t *testing.T) {
	testCases := []struct {
		target         int
		targetMin      int
		maxCap         int
		initInuse      int
		initAvailable  int
		initInvalid    int
		releaseId      string
		releaseInvalid bool
	}{
		{3, 5, 20, 5, 5, 0, "ID-2", false},
		{3, 5, 20, 5, 5, 0, "ID-6", true},
		{3, 5, 20, 5, 5, 0, "no-exist", true},
	}
	exec := func(arg struct {
		target         int
		targetMin      int
		maxCap         int
		initInuse      int
		initAvailable  int
		initInvalid    int
		releaseId      string
		releaseInvalid bool
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		err := pool.Release(arg.releaseId)
		if arg.releaseInvalid {
			assert.ErrorIs(t, err, ErrResourceInvalid)
		} else {
			assert.NoError(t, err)
		}
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestReleaseAfterAllocate(t *testing.T) {
	factory := newMockObjectFactory(20)
	pool := createPool(factory, 3, 5, 20, false, 2, 0, 0, defaultMonitorInterval)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r1, err := pool.Allocate(ctx, "", "")
	assert.NoError(t, err)
	r2, err := pool.Allocate(ctx, "", "")
	assert.NoError(t, err)
	r3, err := pool.Allocate(ctx, "", "")
	assert.NoError(t, err)
	r4, err := pool.Allocate(ctx, "", "")
	assert.NoError(t, err)
	r5, err := pool.Allocate(ctx, "", "")
	assert.NoError(t, err)
	err = pool.Release(r1.GetID())
	assert.NoError(t, err)
	err = pool.Release(r2.GetID())
	assert.NoError(t, err)
	err = pool.Release(r3.GetID())
	assert.NoError(t, err)
	err = pool.Release(r4.GetID())
	assert.NoError(t, err)
	err = pool.Release(r5.GetID())
	assert.NoError(t, err)
}

func TestAllocateConcurrencyLessThanCap(t *testing.T) {
	testCases := []struct {
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}{
		{10, 0, 2, 0},
		{10, 1, 2, 1},
	}
	exec := func(arg struct {
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, 0, 0, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		wg := sync.WaitGroup{}
		for i := 0; i < math.Max(0, arg.maxCap-arg.initInuse); i++ {
			wg.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			go func(index int) {
				res, err := pool.Allocate(ctx, "", "")
				if err != nil {
					t.Logf("concurrency %d err: %v", index, err)
					assert.NoError(t, err)
				}
				t.Logf("Concurrency allocate[%d]: %+v", index, res)
				cancel()
				wg.Done()
			}(i)
		}
		wg.Wait()
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestAllocateConcurrencyMoreThanCap(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}{
		{2, 0, 10, 0, 2, 0},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		wg := sync.WaitGroup{}
		for i := 0; i < arg.maxCap+5; i++ {
			wg.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			go func() {
				res, _ := pool.Allocate(ctx, "", "")
				t.Logf("Concurrency allocate: %+v", res)
				cancel()
				wg.Done()
			}()
		}
		wg.Wait()
		assert.Equal(t, factory.getCreated(), arg.maxCap-arg.initAvailable)
		return true, nil
	}
	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %v not pass, %v", testCase, err))
	}
}

func TestGCAvailableAppear(t *testing.T) {
	testCases := []struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}{
		{3, 5, 20, 0, 0, 0},
		{5, 3, 20, 0, 0, 0},
		{3, 5, 20, 2, 1, 0},
		{0, 0, 10, 2, 1, 0},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initInuse     int
		initAvailable int
		initInvalid   int
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, arg.initInuse, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		usedMap := map[string]types.NetResourceAllocated{}
		for i := 0; i < arg.initInuse; i++ {
			usedMap[newId(i)] = types.NetResourceAllocated{
				Owner:    newOwner(i),
				Resource: &types.MockNetResource{ID: newId(i)},
			}
		}
		cnt := 0
		podResID := ""
		for i := 0; i < (arg.maxCap-arg.initInuse)/2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			pod := fmt.Sprintf("podNew-%d", i)
			res, err := pool.Allocate(ctx, "", pod)
			cancel()
			assert.NoError(t, err)
			usedMap[res.GetID()] = types.NetResourceAllocated{
				Owner:    pod,
				Resource: res,
			}
			podResID = res.GetID()
			cnt++
		}

		time.Sleep(3 * time.Second) // let pool get target

		inuse := cnt + arg.initInuse
		totalCnt := math.Min(arg.maxCap, inuse+arg.target+math.Max(0, arg.targetMin-inuse-arg.target))
		snap, err := pool.GetSnapshot()
		assert.NoError(t, err)
		assert.Equal(t, totalCnt, len(snap.PoolSnapshot()))
		assert.Equal(t, len(snap.MetaSnapshot()), len(snap.PoolSnapshot()))

		newRes := factory.Add(1)

		if podResID != "" {
			_, exist := snap.PoolSnapshot()[podResID]
			assert.Equal(t, true, exist)
			delete(usedMap, podResID)
			err = pool.GC(func() (map[string]types.NetResourceAllocated, error) {
				return usedMap, nil
			})
			assert.NoError(t, err)
			snap, err = pool.GetSnapshot()
			assert.NoError(t, err)
			assert.Equal(t, types.ResStatusAvailable, snap.PoolSnapshot()[podResID].GetStatus())
			assert.Equal(t, types.ResStatusAvailable, snap.PoolSnapshot()[newRes[0].GetID()].GetStatus())
			assert.Equal(t, totalCnt+1, len(snap.PoolSnapshot()))
			assert.Equal(t, len(snap.MetaSnapshot()), len(snap.PoolSnapshot()))
		}
		return true, nil
	}

	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %+v not pass, %v", testCase, err))
	}
}

func TestGCResourceDisappear(t *testing.T) {
	testCases := []struct {
		target    int
		targetMin int
		maxCap    int

		initAvailable int
		initInvalid   int
	}{
		{3, 5, 20, 0, 0},
		{5, 3, 20, 0, 0},
		{3, 5, 20, 1, 0},
		{0, 0, 10, 1, 0},
	}
	exec := func(arg struct {
		target        int
		targetMin     int
		maxCap        int
		initAvailable int
		initInvalid   int
	}) (bool, error) {
		factory := newMockObjectFactory(arg.maxCap)
		pool := createPool(factory, arg.target, arg.targetMin, arg.maxCap, false, 0, arg.initAvailable, arg.initInvalid, defaultMonitorInterval)
		usedMap := map[string]types.NetResourceAllocated{}

		cnt := 0
		podResID := ""
		for i := 0; i < arg.maxCap/2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			pod := fmt.Sprintf("podNew-%d", i)
			res, err := pool.Allocate(ctx, "", pod)
			cancel()
			assert.NoError(t, err)
			usedMap[res.GetID()] = types.NetResourceAllocated{
				Owner:    pod,
				Resource: res,
			}
			podResID = res.GetID()
			cnt++
		}

		time.Sleep(3 * time.Second) // let pool get target

		inuse := cnt
		totalCnt := math.Min(arg.maxCap, inuse+arg.target+math.Max(0, arg.targetMin-inuse-arg.target))
		snap, err := pool.GetSnapshot()
		assert.NoError(t, err)
		assert.Equal(t, totalCnt, len(snap.PoolSnapshot()))
		assert.Equal(t, len(snap.MetaSnapshot()), len(snap.PoolSnapshot()))

		list, err := factory.List()
		assert.NoError(t, err)
		disAppearResID := ""
		for _, res := range list[types.ResStatusNormal] {
			if _, exist := usedMap[res.GetID()]; exist {
				continue
			}
			if disAppearResID != "" {
				break
			}
			disAppearResID = res.GetID()
		}

		if disAppearResID != "" {
			delete(factory.objects, disAppearResID)
			totalCnt--
		}

		if podResID != "" {
			_, exist := snap.PoolSnapshot()[podResID]
			assert.Equal(t, true, exist)
			delete(usedMap, podResID)
			err = pool.GC(func() (map[string]types.NetResourceAllocated, error) {
				return usedMap, nil
			})
			assert.NoError(t, err)
			snap, err = pool.GetSnapshot()
			assert.NoError(t, err)
			assert.Equal(t, types.ResStatusAvailable, snap.PoolSnapshot()[podResID].GetStatus())
			_, exist = snap.PoolSnapshot()[disAppearResID]
			assert.Equal(t, false, exist)
			assert.Equal(t, totalCnt, len(snap.PoolSnapshot()))
			assert.Equal(t, len(snap.MetaSnapshot()), len(snap.PoolSnapshot()))
		}
		return true, nil
	}

	for _, testCase := range testCases {
		t.Logf("start testCase: %+v", testCase)
		paas, err := exec(testCase)
		assert.Equalf(t, true, paas, fmt.Sprintf("TestCase %+v not pass, %v", testCase, err))
	}
}

func TestCapProbe(t *testing.T) {
	factory := newMockObjectFactory(20)
	pool := createPool(factory, 0, 0, 0, true, 0, 0, 0, 10*time.Second)
	assert.Equal(t, 20, pool.GetResourceLimit())
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := pool.Allocate(ctx, "", newOwner(i))
		cancel()
		assert.NoError(t, err)
	}
	factory.setResourceLimit(10)

	for i := 0; i < 15; i++ {
		err := pool.Release(newId(i))
		assert.NoError(t, err)
	}

	time.Sleep(15 * time.Second) // wait reduce

	assert.Equal(t, 10, pool.GetResourceLimit())
	snap, err := pool.GetSnapshot()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(snap.PoolSnapshot()))

	for i := 0; i < 6; i++ {
		for try := 0; try < 2; try++ {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err = pool.Allocate(ctx, "", newOwner(i+23))
			cancel()
			if err == nil {
				break
			}
		}
		if i < 5 {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, ErrNoResourceAvailable)
		}
	}
}

func TestReCfgCache(t *testing.T) {
	factory := newMockObjectFactory(20)
	pool := createPool(factory, 3, 5, 0, true, 1, 1, 1, 5*time.Second)
	assert.Equal(t, 20, pool.GetResourceLimit())
	time.Sleep(5 * time.Second)
	snap, err := pool.GetSnapshot()
	assert.NoError(t, err)
	poolRes := snap.PoolSnapshot()
	available := 0
	for _, item := range poolRes {
		if item.GetStatus() == types.ResStatusAvailable {
			available++
		}
	}
	assert.Equal(t, 5, len(poolRes))
	assert.Equal(t, 4, available)

	pool.ReCfgCache(7, 4)
	time.Sleep(6 * time.Second)
	snap, err = pool.GetSnapshot()
	poolRes = snap.PoolSnapshot()
	assert.NoError(t, err)

	available = 0
	for _, item := range poolRes {
		if item.GetStatus() == types.ResStatusAvailable {
			available++
		}
	}
	assert.Equal(t, 8, len(poolRes))
	assert.Equal(t, 7, available)

	pool.ReCfgCache(0, 0)
	time.Sleep(6 * time.Second)
	snap, err = pool.GetSnapshot()
	poolRes = snap.PoolSnapshot()
	assert.NoError(t, err)
	available = 0
	for _, item := range poolRes {
		if item.GetStatus() == types.ResStatusAvailable {
			available++
		}
	}
	assert.Equal(t, 1, len(poolRes))
	assert.Equal(t, 0, available)
}
