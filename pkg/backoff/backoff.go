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

package backoff

import (
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	DefaultKey     = ""
	APIWriteOps    = "api_write_ops"
	APIStatusWait  = "api_status_wait"
	APIFastRetry   = "api_fast_retry"
	WaitCRDStatus  = "wait_crd_status"
	MetaStatusWait = "meta_status_wait"
)

var backoffMap = map[string]wait.Backoff{
	DefaultKey: {
		Duration: time.Second * 2,
		Factor:   1.5,
		Jitter:   0.3,
		Steps:    6,
	},
	APIWriteOps: {
		Duration: time.Second * 4,
		Factor:   1.5,
		Jitter:   0.5,
		Steps:    6,
	},
	APIStatusWait: {
		Duration: time.Second * 5,
		Factor:   1.5,
		Jitter:   0.5,
		Steps:    8,
	},
	APIFastRetry: {
		Duration: time.Millisecond * 500,
		Factor:   1.7,
		Jitter:   0.3,
		Steps:    6,
	},
	WaitCRDStatus: {
		Duration: time.Second * 5,
		Factor:   2,
		Jitter:   0.3,
		Steps:    3,
	},
	MetaStatusWait: {
		Duration: time.Millisecond * 1100,
		Factor:   1,
		Jitter:   0.2,
		Steps:    10,
	},
}

// BackOff return a specific wait.Backoff according to the key.
func BackOff(key string) wait.Backoff {
	if b, exist := backoffMap[key]; exist {
		return b
	}

	return backoffMap[DefaultKey]
}
