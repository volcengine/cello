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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/volcengine/cello/pkg/store"
	"github.com/volcengine/cello/types"
)

// PodPersistenceManager is the interface to persist pod information.
type PodPersistenceManager interface {
	// Get returns the pod with the given namespace and name.
	Get(podNamespace, podName string) (*types.Pod, error)
	// List returns all pods.
	List() ([]*types.Pod, error)
	// Put persists the given pod.
	Put(pod *types.Pod) error
	// Delete deletes the pod with the given namespace and name.
	Delete(podNamespace, podName string) error
	// Close closes the persistence manager.
	Close()
}

type podPersistenceManager struct {
	storage store.Interface
}

func (ppm *podPersistenceManager) key(podNamespace, podName string) string {
	return podNamespace + "/" + podName
}

func (ppm *podPersistenceManager) Get(podNamespace, podName string) (*types.Pod, error) {
	pod, err := ppm.storage.Get(ppm.key(podNamespace, podName))
	if err != nil {
		return nil, err
	}
	return pod.(*types.Pod), nil
}

func (ppm *podPersistenceManager) List() ([]*types.Pod, error) {
	rawPods := ppm.storage.List()
	var pods []*types.Pod
	for _, pod := range rawPods {
		pods = append(pods, pod.(*types.Pod))
	}

	return pods, nil
}

func (ppm *podPersistenceManager) Put(pod *types.Pod) error {
	return ppm.storage.Put(ppm.key(pod.Namespace, pod.Name), pod)
}

func (ppm *podPersistenceManager) Delete(podNamespace, podName string) error {
	return ppm.storage.Delete(ppm.key(podNamespace, podName))
}

func (ppm *podPersistenceManager) Close() {
	ppm.storage.Close()
}

func newPodPersistenceManager(dbPath, dbName string) (*podPersistenceManager, error) {
	storage, err := store.NewDiskStorage(dbName, dbPath,
		json.Marshal,
		func(bytes []byte) (interface{}, error) {
			pod := &types.Pod{}
			return pod, json.Unmarshal(bytes, &pod)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create persistence storage failed: %w", err)
	}
	ppm := &podPersistenceManager{storage: storage}
	return ppm, nil
}

type getPersistencePod struct {
	podPersistence PodPersistenceManager
}

func (p *getPersistencePod) Handle(c *gin.Context) {
	podNameSpace := c.Query("podNameSpace")
	podName := c.Query("podName")
	if podNameSpace == "" && podName == "" {
		pods, err := p.podPersistence.List()
		if err != nil {
			_ = c.Error(fmt.Errorf("failed to list pod from persistence: %v", err))
			return
		}
		c.JSON(http.StatusOK, pods)
	} else {
		pod, err := p.podPersistence.Get(podNameSpace, podName)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				c.JSON(http.StatusOK, &types.Pod{})
				return
			}
			_ = c.Error(fmt.Errorf("failed to get pod from persistence: %v", err))
			return
		}
		c.JSON(http.StatusOK, pod)
	}
}

func newGetPersistencePodHandler(p PodPersistenceManager) Handler {
	return &getPersistencePod{
		podPersistence: p,
	}
}
