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

package signal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestSignal(t *testing.T) {
	stopCh := make(chan struct{})
	sig := make(chan SigData)

	err := RegisterChannel(WakeGC, sig)
	assert.NoError(t, err)
	go wait.JitterUntil(func() {
		NotifySignal(WakeGC, SigWakeGC)
	}, time.Second, 0.2, true, stopCh)

	go func() {
		for {
			select {
			case <-sig:
				t.Logf("Recevice signal")
				time.Sleep(2 * time.Second)
			case <-stopCh:
				return
			}
		}
	}()

	time.Sleep(5 * time.Second)
	MuteChannel(WakeGC)
	close(sig)
	time.Sleep(2 * time.Second)
	close(stopCh)
	time.Sleep(2 * time.Second)
}
