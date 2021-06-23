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

package k8s

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/volcengine/cello/types"
)

func TestPatchTrunkInfo(t *testing.T) {
	nodeName := "fake-node"
	k8sClient := fake.NewSimpleClientset()

	_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), &corev1.Node{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
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

	k8sService, err := NewK8sService(nodeName, k8sClient)
	assert.NoError(t, err)

	trunkENI := "eni-saj223d2344s"

	t.Run("TestAdd", func(t *testing.T) {
		t.Parallel()
		trunkInfo := types.TrunkInfo{
			EniID:       trunkENI,
			Mac:         "ef:ef:ef:ef:ef:ef",
			BranchLimit: 6,
		}
		err = k8sService.PatchTrunkInfo(&trunkInfo)
		assert.NoError(t, err)
		node, err := k8sService.GetLocalNode(context.Background())
		assert.NoError(t, err)
		var trunkInfoGot types.TrunkInfo
		err = json.Unmarshal([]byte(node.Annotations[types.AnnotationTrunkENI]), &trunkInfoGot)
		assert.NoError(t, err)
		assert.Equal(t, trunkInfo, trunkInfoGot)
	})

	t.Run("TestDelete", func(t *testing.T) {
		trunkInfo := types.TrunkInfo{
			EniID:       trunkENI,
			Mac:         "ef:ef:ef:ef:ef:ef",
			BranchLimit: 6,
		}
		err = k8sService.PatchTrunkInfo(&trunkInfo)
		assert.NoError(t, err)
		node, err := k8sService.GetLocalNode(context.Background())
		assert.NoError(t, err)
		_, exist := node.Annotations[types.AnnotationTrunkENI]
		assert.Equal(t, true, exist)
		err = k8sService.PatchTrunkInfo(nil)
		assert.NoError(t, err)
		node, err = k8sService.GetLocalNode(context.Background())
		assert.NoError(t, err)
		_, exist = node.Annotations[types.AnnotationTrunkENI]
		t.Log(node.Annotations[types.AnnotationTrunkENI])
		assert.Equal(t, false, exist)
	})
}
