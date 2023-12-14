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

package cidr

import (
	"fmt"
	"net"
	"sync"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
	k8sErr "k8s.io/apimachinery/pkg/util/errors"

	"github.com/volcengine/cello/pkg/utils/logger"
)

var (
	log = logger.GetLogger().WithFields(logger.Fields{"subsys": "cidrAllocator"})
)

// AllocatorGroup Manage multiple allocators for multiple sets of cidr
type AllocatorGroup struct {
	ipamAllocators *sync.Map
}

type ipamSet struct {
	ipAllocator *allocator.IPAllocator
	store       backend.Store
	ranges      *allocator.RangeSet
}

func NewAllocatorGroup(c *Config) (*AllocatorGroup, error) {
	err := validateConfig(c)
	if err != nil {
		return nil, err
	}
	group := &AllocatorGroup{
		ipamAllocators: &sync.Map{},
	}
	for id, rangeSet := range c.Ranges {
		store, err := disk.New(id, c.DataDir)
		if err != nil {
			return nil, err
		}
		log.Infof("Create allocator for %s, id %s", rangeSet.String(), id)
		group.ipamAllocators.Store(id, ipamSet{
			ipAllocator: allocator.NewIPAllocator(rangeSet, store, 0),
			store:       store,
			ranges:      rangeSet,
		})
	}
	return group, nil
}

// Get allocates an IP from special allocator
func (a *AllocatorGroup) Get(rangeSetId, ownerId, ifName string, requestedIP net.IP) (*current.IPConfig, error) {

	alloc, exist := a.ipamAllocators.Load(rangeSetId)
	if !exist {
		return nil, fmt.Errorf("get allocator by %s failed, not exist", rangeSetId)
	}

	addresses := alloc.(ipamSet).store.GetByID(ownerId, ifName)
	if len(addresses) == 1 {
		r, err := alloc.(ipamSet).ranges.RangeFor(addresses[0])
		if err != nil {
			return nil, err
		}
		err = canonicalizeIP(&addresses[0])
		if err != nil {
			return nil, err
		}
		return &current.IPConfig{
			Address: net.IPNet{
				IP:   addresses[0],
				Mask: r.Subnet.Mask,
			},
			Gateway: r.Gateway,
		}, nil
	}
	return alloc.(ipamSet).ipAllocator.Get(ownerId, ifName, requestedIP)
}

// Release clears all IPs allocated for the container with given ID
func (a *AllocatorGroup) Release(rangeSetId, ownerId, ifName string) error {
	var rangeSetIdList []string
	if rangeSetId == "" {
		a.ipamAllocators.Range(func(key, value any) bool {
			if ipAddr := value.(ipamSet).store.GetByID(ownerId, ifName); len(ipAddr) != 0 {
				rangeSetIdList = append(rangeSetIdList, key.(string))
				return false
			}
			return true
		})
	} else {
		rangeSetIdList = append(rangeSetIdList, rangeSetId)
	}

	var errList []error
	for _, id := range rangeSetIdList {
		alloc, exist := a.ipamAllocators.Load(id)
		if !exist {
			errList = append(errList, fmt.Errorf("get allocater by %s failed, not exist", rangeSetId))
			continue
		}
		err := alloc.(ipamSet).ipAllocator.Release(ownerId, ifName)
		if err != nil {
			errList = append(errList, err)
		}
	}
	return k8sErr.NewAggregate(errList)
}

func (a *AllocatorGroup) AddRangeSet(rangeSetId, dir string, set *allocator.RangeSet) error {
	store, err := disk.New(rangeSetId, dir)
	if err != nil {
		return err
	}

	a.ipamAllocators.LoadOrStore(rangeSetId, ipamSet{
		ipAllocator: allocator.NewIPAllocator(set, store, 0),
		store:       store,
		ranges:      set,
	})
	return nil
}

func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}
