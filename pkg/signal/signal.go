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
	"fmt"

	"github.com/volcengine/cello/pkg/utils/logger"
)

type SigData uint32

var log = logger.GetLogger().WithFields(logger.Fields{"subSys": "signal"})

const (
	WakeGC = "wakeGC"
)

const (
	SigWakeGC = iota
)

var (
	signalChannels map[string]chan<- SigData
	muteSignal     map[string]struct{}
)

// RegisterChannel register a notify channel for event.
func RegisterChannel(signal string, ch chan<- SigData) error {
	if _, exist := signalChannels[signal]; exist {
		return fmt.Errorf("register a exist signal")
	}
	signalChannels[signal] = ch
	return nil
}

// NotifySignal non-blocking notification.
func NotifySignal(signal string, data SigData) {
	if _, exist := muteSignal[signal]; exist {
		log.Infof("Signal %s muted", signal)
		return
	}
	if ch, exist := signalChannels[signal]; exist {
		select {
		case ch <- data:
		default:
			log.Infof("Signal [%v %v] processing", signal, data)
		}
	}
}

// MuteChannel tells to not send any signal to a particular channel.
func MuteChannel(signal string) {
	muteSignal[signal] = struct{}{}
}

// UnmuteChannel tells to allow sending new signal to a particular channel.
func UnmuteChannel(signal string) {
	delete(muteSignal, signal)
}

func init() {
	signalChannels = map[string]chan<- SigData{}
	muteSignal = map[string]struct{}{}
}
