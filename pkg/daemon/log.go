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
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/volcengine/cello/pkg/utils/logger"
)

var (
	log = logger.GetLogger().WithFields(logger.Fields{"subsys": "daemon"})
)

type setLogLevel struct{}

func (l *setLogLevel) Handle(c *gin.Context) {
	logLevel := c.Query("logLevel")
	log.SetLogLevel(logLevel)
	log.Infof("Set logLevel to %s", logLevel)
	c.JSON(http.StatusOK, fmt.Sprintf("set log to level %s\n", logLevel))
}

func newSetLogLevelHandler() Handler {
	return &setLogLevel{}
}
