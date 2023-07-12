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

package cello

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"

	celloMeta "github.com/volcengine/cello/pkg/plugins/cni/cello-meta"
	"github.com/volcengine/cello/pkg/plugins/types"
)

const (
	componentName = "cello"
)

func init() {
	celloMeta.RegisterPreNetworkMetaShim(types.CelloChainer, &celloShim{})
	celloMeta.RegisterExecMetaShim(componentName, &celloShim{})
}

type celloShim struct {
}

func (v *celloShim) PreAddNetwork(rt *libcni.RuntimeConf, delegate *celloMeta.DelegateNetConf) error {
	return v.preAddDelNetworkSameOpt(rt, delegate)
}

func (v *celloShim) PreDelNetwork(rt *libcni.RuntimeConf, delegate *celloMeta.DelegateNetConf) error {
	return v.preAddDelNetworkSameOpt(rt, delegate)
}

func (v *celloShim) ExecCMDAdd(args *skel.CmdArgs) (cniTypes.Result, error) {
	return InternalAdd(args)
}

func (v *celloShim) ExecCMDDel(args *skel.CmdArgs) error {
	return InternalDel(args)
}

func (v *celloShim) preAddDelNetworkSameOpt(_ *libcni.RuntimeConf, delegate *celloMeta.DelegateNetConf) error {

	// 1. if net is first(master) eth, make sure use cilium chain
	if delegate.Index == 0 {
		if err := v.addServiceChain(delegate); err != nil {
			return err
		}
		// if net is not first eth, InternalDel cilium chain
	} else {
		if err := v.delServiceChain(delegate); err != nil {
			return err
		}
	}

	return nil
}

func (v *celloShim) addServiceChain(delegate *celloMeta.DelegateNetConf) error {
	if !delegate.ConfListPlugin {
		return fmt.Errorf("no support InternalAdd cni chain")
	}
	if len(delegate.ConfList.Plugins) == 0 {
		return fmt.Errorf("addServiceChain celloShim: vpc cni plugin is nil")
	}

	var rawConfig map[string]interface{}
	var err error

	err = json.Unmarshal(delegate.Bytes, &rawConfig)
	if err != nil {
		return fmt.Errorf("addServiceChain: failed to unmarshal inBytes: %v", err)
	}

	pList, ok := rawConfig["plugins"]
	if !ok {
		return fmt.Errorf("addServiceChain: unable to get plugin list")
	}

	pMap, ok := pList.([]interface{})
	if !ok {
		return fmt.Errorf("addServiceChain: unable to typecast plugin list")
	}

	var tmpMap []interface{}
	for idx, plugin := range pMap {
		currentPlugin, ok := plugin.(map[string]interface{})
		if !ok {
			return fmt.Errorf("addServiceChain: unable to typecast plugin #%d", idx)
		}

		if currentPlugin["type"] == "cilium-cni" {
			return nil
		}
		tmpMap = append(tmpMap, currentPlugin)
	}

	tmpMap = append(tmpMap, &cniTypes.NetConf{
		Name: "cilium",
		Type: "cilium-cni",
	})

	rawConfig["plugins"] = tmpMap
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("addServiceChain: failed to re-marshal: %v", err)
	}

	delegate.Bytes = configBytes
	return nil
}

func (v *celloShim) delServiceChain(delegate *celloMeta.DelegateNetConf) error {
	if !delegate.ConfListPlugin {
		return nil
	}

	if len(delegate.ConfList.Plugins) == 0 {
		return fmt.Errorf("delServiceChain celloShim: vpc cni plugin is nil")
	} else if len(delegate.ConfList.Plugins) == 1 {
		return nil
	}

	var rawConfig map[string]interface{}
	var err error

	err = json.Unmarshal(delegate.Bytes, &rawConfig)
	if err != nil {
		return fmt.Errorf("delServiceChain: failed to unmarshal inBytes: %v", err)
	}

	pList, ok := rawConfig["plugins"]
	if !ok {
		return fmt.Errorf("delServiceChain: unable to get plugin list")
	}

	pMap, ok := pList.([]interface{})
	if !ok {
		return fmt.Errorf("delServiceChain: unable to typecast plugin list")
	}

	var tmpMap []interface{}
	for idx, plugin := range pMap {
		currentPlugin, ok := plugin.(map[string]interface{})
		if !ok {
			return fmt.Errorf("delServiceChain: unable to typecast plugin #%d", idx)
		}

		if currentPlugin["type"] == "cello" {
			// Ignore localFastPath config for secondary interface.
			currentPlugin["localFastPath"] = false
			currentPlugin["redirectToHostCIDRs"] = nil
		}

		if currentPlugin["type"] != "cilium-cni" {
			tmpMap = append(tmpMap, currentPlugin)
		}

	}
	rawConfig["plugins"] = tmpMap
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("delServiceChain: failed to re-marshal: %v", err)
	}
	delegate.Bytes = configBytes
	return nil
}
