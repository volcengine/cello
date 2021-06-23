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
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/volcengine/cello/pkg/pool"
	"github.com/volcengine/cello/types"
)

// ResourceManager is the interface to manage network resources.
type ResourceManager interface {
	// Name returns the name of the resource manager.
	Name() string
	// Allocate allocates a NetResource.
	Allocate(ctx *netContext, prefer string) (types.NetResource, error)
	// Release releases the given NetResource.
	Release(ctx *netContext, resource *types.VPCResource) error
	// GetSnapshot returns the snapshot of the resource manager.
	GetSnapshot() (pool.ResourcePoolSnapshot, error)
	// GetPoolStatus returns the status of the resource pool.
	GetPoolStatus() pool.Status
	// GetResourceLimit returns the limit of the resource manager.
	GetResourceLimit() int
}

type getResourceManagerSnapshot struct {
	daemon *daemon
}

func (s *getResourceManagerSnapshot) Handle(c *gin.Context) {
	info := map[string]struct {
		Pool map[string]types.NetResourceSnapshot
		Meta map[string]types.NetResourceSnapshot
	}{}

	for resType, mgr := range s.daemon.managers {
		snapshot, err := mgr.GetSnapshot()
		if err != nil {
			_ = c.Error(err)
			return
		}
		poolRes := map[string]types.NetResourceSnapshot{}
		metaRes := map[string]types.NetResourceSnapshot{}
		for id, item := range snapshot.PoolSnapshot() {
			poolRes[id] = *item.(*types.NetResourceSnapshot)
		}
		for id, item := range snapshot.MetaSnapshot() {
			metaRes[id] = *item.(*types.NetResourceSnapshot)
		}
		info[resType] = struct {
			Pool map[string]types.NetResourceSnapshot
			Meta map[string]types.NetResourceSnapshot
		}{Pool: poolRes, Meta: metaRes}
	}
	c.JSON(http.StatusOK, info)
}

func newGetResourceSnapshotHandler(d *daemon) Handler {
	return &getResourceManagerSnapshot{
		daemon: d,
	}
}

type getPoolStatus struct {
	daemon *daemon
}

func (s *getPoolStatus) Handle(c *gin.Context) {
	info := map[string]pool.Status{}

	for resType, mgr := range s.daemon.managers {
		info[resType] = mgr.GetPoolStatus()
	}
	c.JSON(http.StatusOK, info)
}

func newGetPoolStatusHandler(d *daemon) Handler {
	return &getPoolStatus{
		daemon: d,
	}
}
