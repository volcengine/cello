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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/types"
)

func TestConfigMerge(t *testing.T) {
	nodeName := "fake-node"
	k8sClient := fake.NewSimpleClientset()
	nodeConfigName := "for-node"
	nodeConfigNs := "node-config"

	// Prepare a node
	_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), &corev1.Node{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			Labels: map[string]string{
				types.LabelNodeDynamicConfigKey: fmt.Sprintf("%s.%s", nodeConfigNs, nodeConfigName),
			},
		},
		Spec: corev1.NodeSpec{},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeExternalIP,
					Address: "172.16.0.3",
				},
				{
					Type:    corev1.NodeHostName,
					Address: "172.16.0.3",
				},
			},
		},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	k8sService, err := k8s.NewK8sService(nodeName, k8sClient)
	assert.NoError(t, err)

	// Prepare cluster config
	clusterConfig := &Config{
		RamRole:                     datatype.String("KubernetesNodeRoleForECS"),
		OpenApiAddress:              datatype.String("open-boe-stable.volcengineapi.com"),
		SecurityGroups:              []string{"sg-12345", "sg-678910"},
		Subnets:                     []string{"subnet-3repsnxeltngg5zsk2ib51f9u", "subnet-2bz61abxg9f5s2dx0eg4z9bmo"},
		ReconcileIntervalSec:        datatype.Uint32(DefaultReconcileIntervalSec),
		PoolTarget:                  datatype.Uint32(3),
		PoolTargetMin:               datatype.Uint32(5),
		PoolMonitorIntervalSec:      datatype.Uint32(DefaultPoolMonitorIntervalSec),
		SubnetStatAgingSec:          datatype.Uint32(DefaultSubnetStatAgingSec),
		SubnetStatUpdateIntervalSec: datatype.Uint32(DefaultSubnetStatUpdateIntervalSec),
		EnableTrunk:                 datatype.Bool(false),
		NetworkMode:                 datatype.String(NetworkModeENIShare),
		IPFamily:                    datatype.String(types.IPFamilyIPv4),
	}

	configData, _ := json.Marshal(clusterConfig)
	_, err = k8sClient.CoreV1().ConfigMaps(Namespace).Create(context.Background(), &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cello-config",
			Namespace: Namespace,
		},
		Data: map[string]string{
			"conf": string(configData),
		},
		BinaryData: nil,
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	// Prepare cluster config
	nodeConfig := &Config{
		RamRole:                     datatype.String("ForTest"),
		OpenApiAddress:              datatype.String("ForTest"),
		SecurityGroups:              []string{"sg-abcdef", "sg-ghijklm"},
		Subnets:                     []string{"subnet-2bznh8mcy0wzk2dx0efgng9q8", "subnet-2bznh8ievst1c2dx0efzr4q2k"},
		ReconcileIntervalSec:        datatype.Uint32(DefaultReconcileIntervalSec),
		PoolTarget:                  datatype.Uint32(5),
		PoolTargetMin:               datatype.Uint32(10),
		PoolTargetLimit:             datatype.Float64(0.8),
		PoolMonitorIntervalSec:      datatype.Uint32(DefaultPoolMonitorIntervalSec),
		SubnetStatAgingSec:          datatype.Uint32(DefaultSubnetStatAgingSec),
		SubnetStatUpdateIntervalSec: datatype.Uint32(DefaultSubnetStatUpdateIntervalSec),
		EnableTrunk:                 datatype.Bool(true),
		NetworkMode:                 datatype.String(NetworkModeENIExclusive),
		IPFamily:                    datatype.String(types.IPFamilyIPv6),
	}

	configData, _ = json.Marshal(nodeConfig)
	_, err = k8sClient.CoreV1().ConfigMaps("node-config").Create(context.Background(), &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeConfigName,
			Namespace: nodeConfigNs,
		},
		Data: map[string]string{
			"conf": string(configData),
		},
		BinaryData: nil,
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	cfg, err := ParseConfig(k8sService)
	assert.NoError(t, err)
	assert.Equal(t, *clusterConfig.OpenApiAddress, *cfg.OpenApiAddress)

	// pool config
	assert.Equal(t, *nodeConfig.PoolTarget, *cfg.PoolTarget)
	assert.Equal(t, *nodeConfig.PoolTargetMin, *cfg.PoolTargetMin)
	assert.Equal(t, *nodeConfig.PoolTargetLimit, *cfg.PoolTargetLimit)
	assert.Equal(t, *nodeConfig.EnableTrunk, *cfg.EnableTrunk)
	assert.Equal(t, SourceNodeMerged, *cfg.Source)

	// SecurityGroups
	assert.Equal(t, true, sets.NewString(cfg.SecurityGroups...).Equal(sets.NewString(nodeConfig.SecurityGroups...)))
	// Subnets
	assert.Equal(t, true, sets.NewString(cfg.Subnets...).Equal(sets.NewString(nodeConfig.Subnets...)))
}
