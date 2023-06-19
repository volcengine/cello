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

package meta

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"

	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/metrics"
)

func init() {
	PreNetworkMetaShimFactorys = &PreNetworkMetaShimFactory{
		factory: make(map[string]PreNetworkMetaShim),
	}
	ExecMetaShimFactorys = &ExecMetaShimFactory{
		factory: make(map[string]ExecMetaShim),
	}
}

type PreNetworkMetaShim interface {
	PreAddNetwork(rt *libcni.RuntimeConf, delegate *DelegateNetConf) error
	PreDelNetwork(rt *libcni.RuntimeConf, delegate *DelegateNetConf) error
}

var PreNetworkMetaShimFactorys *PreNetworkMetaShimFactory

func RegisterPreNetworkMetaShim(name string, shim PreNetworkMetaShim) {
	PreNetworkMetaShimFactorys.factory[name] = shim
}

type PreNetworkMetaShimFactory struct {
	factory map[string]PreNetworkMetaShim
}

func (p *PreNetworkMetaShimFactory) PreAddNetwork(rt *libcni.RuntimeConf, delegate *DelegateNetConf) error {
	_, ok := p.factory[delegate.Name]
	if !ok {
		return nil
	}
	return p.factory[delegate.Name].PreAddNetwork(rt, delegate)
}

func (p *PreNetworkMetaShimFactory) PreDelNetwork(rt *libcni.RuntimeConf, delegate *DelegateNetConf) error {
	_, ok := p.factory[delegate.Name]
	if !ok {
		return nil
	}
	return p.factory[delegate.Name].PreDelNetwork(rt, delegate)
}

// ExecMetaShim support execute local function
type ExecMetaShim interface {
	ExecCMDAdd(args *skel.CmdArgs) (cniTypes.Result, error)
	ExecCMDDel(args *skel.CmdArgs) error
}

var ExecMetaShimFactorys *ExecMetaShimFactory

func RegisterExecMetaShim(name string, shim ExecMetaShim) {
	ExecMetaShimFactorys.factory[name] = shim
}

type ExecMetaShimFactory struct {
	factory map[string]ExecMetaShim
}

func (o *ExecMetaShimFactory) ExecCMDAdd(name string, args *skel.CmdArgs) ([]byte, error) {
	_, ok := o.factory[name]
	if !ok {
		return nil, fmt.Errorf("no found plugin")
	}

	start := time.Now()
	result, err := o.factory[name].ExecCMDAdd(args)
	duration := metrics.MsSince(start)
	log.Log.InfoS("ExecCMDAdd time costMillisecond", "cost", fmt.Sprintf("%f", duration), "name", name)

	if err != nil {
		log.Log.ErrorS(err, "ExecCMDAdd error", "name", name)
		return nil, err
	}

	data, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return nil, err
	}
	return data, err
}

func (o *ExecMetaShimFactory) ExecCMDDel(name string, args *skel.CmdArgs) ([]byte, error) {
	_, ok := o.factory[name]
	if !ok {
		return nil, fmt.Errorf("no found plugin")
	}
	start := time.Now()
	err := o.factory[name].ExecCMDDel(args)
	duration := metrics.MsSince(start)
	log.Log.InfoS("ExecCMDDel time cost Millisecond", "cost", fmt.Sprintf("%f", duration), "name", name)
	if err != nil {
		log.Log.ErrorS(err, "ExecCMDDel error", "name", name)
	}
	return nil, err
}

func (o *ExecMetaShimFactory) IsExistPlugin(name string) bool {
	_, ok := o.factory[name]
	return ok
}
