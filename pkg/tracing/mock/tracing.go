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

package mock

import (
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/utils/logger"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "fake_tracing"})

func NewFakeTracker() *tracing.Tracer {
	t := tracing.NewTracer()
	podEventRecord := func(podName, podNamespace, eventType, reason, message string) error {
		log.Infof("%s  %s  From %s/%s  %s", eventType, reason, podNamespace, podName, message)
		return nil
	}
	nodeEventRecord := func(eventType, reason, message string) {
		log.Infof("%s  %s  %s", eventType, reason, message)
	}
	t.RegisterEventRecorder(nodeEventRecord, podEventRecord)
	return t
}
