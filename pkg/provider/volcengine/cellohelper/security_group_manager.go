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

package cellohelper

import (
	"fmt"
	"sync"
)

type SecurityGroupManager interface {
	// GetSecurityGroups get security groups used by pods
	GetSecurityGroups() []string
	// UpdateSecurityGroups update security groups used by pods
	UpdateSecurityGroups(sec []string) error
}

type securityGroupManager struct {
	lock           sync.RWMutex
	securityGroups []string
}

func (m *securityGroupManager) GetSecurityGroups() []string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.securityGroups
}

func (m *securityGroupManager) UpdateSecurityGroups(sec []string) error {
	if len(sec) == 0 {
		return fmt.Errorf("security groups is empty")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.securityGroups = sec
	log.Infof("SecurityGroups update to %v", m.securityGroups)
	return nil
}

func NewSecurityGroupManager() SecurityGroupManager {
	return &securityGroupManager{
		lock:           sync.RWMutex{},
		securityGroups: []string{},
	}
}
