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
	"context"

	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/types"
)

// netContext is the context for network operation.
type netContext struct {
	context.Context
	pod *types.Pod
	res []types.VPCResource // record resource allocate for rollback
	log logger.Logger
}

func (ctx *netContext) Log() logger.Logger {
	return ctx.log.WithFields(logger.Fields{
		"Namespace":          ctx.pod.Namespace,
		"Name":               ctx.pod.Name,
		"SandboxContainerId": ctx.pod.SandboxContainerId,
	})
}
