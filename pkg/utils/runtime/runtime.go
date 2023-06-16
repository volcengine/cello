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

package runtime

import (
	"runtime"

	"github.com/volcengine/cello/pkg/utils/logger"
)

func logPanic(r interface{}, log logger.Logger) {
	// Same as stdlib http server code. Manually allocate stack trace buffer size
	// to prevent excessively large logs
	const size = 64 << 10
	stacktrace := make([]byte, size)
	stacktrace = stacktrace[:runtime.Stack(stacktrace, false)]
	if _, ok := r.(string); ok {
		log.Errorf("Observed a panic: %s\n%s\n", r, stacktrace)
	} else {
		log.Errorf("Observed a panic: %#v (%v)\n%s", r, r, stacktrace)
	}
}

func HandleCrash(log logger.Logger) {
	if r := recover(); r != nil {
		logPanic(r, log)
	}
}
