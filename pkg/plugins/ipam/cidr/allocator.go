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
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
)

// AllocatorGroup Manage multiple allocators for multiple sets of cidr
type AllocatorGroup struct {
	members   map[string]*allocator.IPAllocator
	stores    map[string]backend.Store
	rangeSets map[string]*allocator.RangeSet
}

func NewAllocatorGroup(c *Config) (*AllocatorGroup, error) {
	group := &AllocatorGroup{
		members:   map[string]*allocator.IPAllocator{},
		stores:    map[string]backend.Store{},
		rangeSets: map[string]*allocator.RangeSet{},
	}
	for id, rangeSet := range c.Ranges {
		store, err := disk.New(id, c.DataDir)
		if err != nil {
			return nil, err
		}
		group.stores[id] = store
		group.members[id] = allocator.NewIPAllocator(&rangeSet, store, 0)
		group.rangeSets[id] = &rangeSet
	}
	return group, nil
}

// Get allocates an IP from special allocator
func (a *AllocatorGroup) Get(rangeSetId, ownerId, ifName string, requestedIP net.IP) (*current.IPConfig, error) {
	alloc, exist := a.members[rangeSetId]
	if !exist {
		return nil, fmt.Errorf("get allocator by %s failed, not exist", rangeSetId)
	}
	store, exist := a.stores[rangeSetId]
	if !exist {
		return nil, fmt.Errorf("get store by %s failed, not exist", rangeSetId)
	}

	addresses := store.GetByID(ownerId, ifName)
	if len(addresses) == 1 {
		r, err := a.rangeSets[rangeSetId].RangeFor(addresses[0])
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
	return alloc.Get(ownerId, ifName, requestedIP)
}

// Release clears all IPs allocated for the container with given ID
func (a *AllocatorGroup) Release(rangeSetId, ownerId, ifName string) error {
	alloc, exist := a.members[rangeSetId]
	if !exist {
		return fmt.Errorf("get allocater by %s failed, not exist", rangeSetId)
	}
	return alloc.Release(ownerId, ifName)
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
