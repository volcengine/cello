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

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/utils/datatype"
)

// GetMergedConfigFromConfigMap get merged config from all configmaps(cluster scope and node scope).
func GetMergedConfigFromConfigMap(k8s k8s.Service) (*DaemonConfig, error) {
	celloConfigMap, err := k8s.GetConfigMap(context.Background(), Namespace, CelloConfigName)
	if err != nil {
		return nil, err
	}
	clusterConfig, err := GetCelloConfigFromConfigMap(celloConfigMap)
	if err != nil {
		return nil, err
	}
	clusterConfig.Source = datatype.String(SourceClusterConfigMap)

	nodeConfig, err := getNodeScopeConfig(service)
	if err != nil {
		log.ErrorS(err, "Get node scope config failed")
	}
	if nodeConfig == nil {
		return clusterConfig, nil
	}
	log.InfoS("Get node scope config", "nodeConfig", nodeConfig.String())

	// Currently, only the following parameters are supported to be configured via node scope configmap
	if nodeConfig.PoolTargetLimit != nil {
		clusterConfig.PoolTargetLimit = nodeConfig.PoolTargetLimit
	}
	if nodeConfig.PoolTarget != nil {
		clusterConfig.PoolTarget = nodeConfig.PoolTarget
	}
	if nodeConfig.PoolTargetMin != nil {
		clusterConfig.PoolTargetMin = nodeConfig.PoolTargetMin
	}
	if nodeConfig.EnableTrunk != nil {
		clusterConfig.EnableTrunk = nodeConfig.EnableTrunk
	}
	if nodeConfig.SecurityGroups != nil {
		clusterConfig.SecurityGroups = nodeConfig.SecurityGroups
	}
	if nodeConfig.Subnets != nil {
		clusterConfig.Subnets = nodeConfig.Subnets
	}
	if nodeConfig.CustomENIQuota != nil {
		clusterConfig.CustomENIQuota = nodeConfig.CustomENIQuota
	}
	if nodeConfig.CustomBranchENIQuota != nil {
		clusterConfig.CustomBranchENIQuota = nodeConfig.CustomBranchENIQuota
	}
	clusterConfig.Source = datatype.String(SourceNodeMerged)
	return clusterConfig, nil
}

// getNodeScopeConfig get cello config from configmap which assigned to node by label.
func getNodeScopeConfig(k8s k8s.Service) (*Config, error) {
	cfName := k8s.GetNodeDynamicConfigName()
	if cfName == "" {
		return nil, nil
	}
	nsAndName := strings.SplitN(cfName, ".", 2)
	if length := len(nsAndName); length != 2 {
		log.ErrorS(nil, "Dynamic config label err[must like nameSpace.name]", "cfName", cfName)
		return nil, fmt.Errorf("dynamic config label %s err[must like nameSpace.name]", cfName)
	}

	celloConfigMap, err := k8s.GetConfigMap(context.Background(), nsAndName[0], nsAndName[1])
	if err != nil {
		return nil, err
	}
	return GetCelloConfigFromConfigMap(celloConfigMap)
}

// GetCelloConfigFromConfigMap get cello config from configmap object.
func GetCelloConfigFromConfigMap(obj interface{}) (*Config, error) {
	configmap, ok := obj.(*v1.ConfigMap)
	if !ok {
		return nil, fmt.Errorf("convert to configmap failed")
	}
	confString, ok := configmap.Data["conf"]
	if !ok {
		return nil, fmt.Errorf("configmap has no conf field")
	}
	celloConfig := &Config{}
	err := json.Unmarshal([]byte(confString), &celloConfig)
	if err != nil {
		return nil, fmt.Errorf("unmarshal config failed, %v", err)
	}
	if len(celloConfig.SecurityGroups) == 0 && len(celloConfig.LegacySecurityGroups) != 0 {
		celloConfig.SecurityGroups = celloConfig.LegacySecurityGroups
	}
	return celloConfig, nil
}
