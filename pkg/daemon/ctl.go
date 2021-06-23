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
	"net"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
)

const (
	// DefaultDebugSocketPath is the default path of debug socket.
	DefaultDebugSocketPath = "/var/run/cello/cello_debug.socket"
	// PodsGetPath is the HTTP path to get pods.
	PodsGetPath = "/pod/get"
	// IPAMSnapshotGetPath is the HTTP path to get ipam snapshot.
	IPAMSnapshotGetPath = "/ipam/snapshot/get"
	// IPAMStatusGetPath is the HTTP path to get ipam status.
	IPAMStatusGetPath = "/ipam/status/get"
	// IPAMLimitGetPath is the HTTP path to get ipam limit.
	IPAMLimitGetPath = "/ipam/limit/get"
	// ConfigGetPath is the HTTP path to get config.
	ConfigGetPath = "/config/get"
	// ConfigLogLevelSetPath is the HTTP path to set log level.
	ConfigLogLevelSetPath = "/config/log/level/set"
	// ConfigSubnetStatusGetPath is the HTTP path to get subnet status.
	ConfigSubnetStatusGetPath = "/config/subnet/status/get"
	// ConfigSecurityGrpStatusGetPath is the HTTP path to get security group status.
	ConfigSecurityGrpStatusGetPath = "/config/securityGrp/status/get"
	// EcsMetaInfoGetPath is the HTTP path to get ecs meta info.
	EcsMetaInfoGetPath = "/ecs/info/get"
	// TaskStatusGetPath is the HTTP path to get task status.
	TaskStatusGetPath = "/task/status/get"
)

// Handler is the interface to handle http request.
type Handler interface {
	Handle(c *gin.Context)
}

// celloCtlAPI is the entity to handle cello ctl api request for debug.
type celloCtlAPI struct {
	debugSocketPath string
	handlers        map[string]map[string]Handler
}

func (d *daemon) newCelloCtlAPI() *celloCtlAPI {
	ctl := &celloCtlAPI{
		debugSocketPath: DefaultDebugSocketPath,
		handlers:        map[string]map[string]Handler{},
	}

	// instance ctl api
	ctl.handlers[http.MethodGet] = map[string]Handler{}
	ctl.handlers[http.MethodGet][ConfigGetPath] = newGetConfigHandler(d)
	ctl.handlers[http.MethodGet][ConfigLogLevelSetPath] = newSetLogLevelHandler()
	ctl.handlers[http.MethodGet][ConfigSubnetStatusGetPath] = newGetSubnetStatHandler(d.subnetManager)
	ctl.handlers[http.MethodGet][ConfigSecurityGrpStatusGetPath] = newGetSecurityGroupHandler(d.securityGroupManager)
	ctl.handlers[http.MethodGet][IPAMSnapshotGetPath] = newGetResourceSnapshotHandler(d)
	ctl.handlers[http.MethodGet][IPAMStatusGetPath] = newGetPoolStatusHandler(d)
	ctl.handlers[http.MethodGet][IPAMLimitGetPath] = newInstanceLimitHandler(d.instanceLimit)
	ctl.handlers[http.MethodGet][PodsGetPath] = newGetPersistencePodHandler(d.podPersistenceManager)
	ctl.handlers[http.MethodGet][EcsMetaInfoGetPath] = newGetInstanceMetaHandler(d.ecsMetaGetter, d.instanceMeta)
	return ctl
}

func (c *celloCtlAPI) start() (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"resp": "ok",
		})
	})

	for method, ctl := range c.handlers {
		for path, handler := range ctl {
			router.Handle(method, path, handler.Handle)
		}
	}

	_ = os.Remove(c.debugSocketPath) // ignore_security_alert
	unixAddr, err := net.ResolveUnixAddr("unix", c.debugSocketPath)
	if err != nil {
		log.Errorf("New socket path failed: %v", err)
		return nil, err
	}

	l, err := net.ListenUnix("unix", unixAddr)
	if err != nil {
		log.Errorf("Listen unix addr failed: %v", err)
		return nil, err
	}

	server := &http.Server{
		Handler: router,
	}

	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Errorf("CliServer panic, %v", err)
			}
		}()
		log.Infof("Start ctl http server")
		err := server.Serve(l)
		if err != nil {
			log.Warnf("Ctl server exit: %v", err)
		}
	}()

	return server, nil
}

type getSubnetStat struct {
	subnet helper.SubnetManager
}

func (m *getSubnetStat) Handle(c *gin.Context) {
	status := m.subnet.Status()
	c.JSON(http.StatusOK, status)
}

func newGetSubnetStatHandler(subnet helper.SubnetManager) Handler {
	return &getSubnetStat{subnet: subnet}
}

type getSecurityGroup struct {
	securityGroup helper.SecurityGroupManager
}

func (s *getSecurityGroup) Handle(c *gin.Context) {
	status := s.securityGroup.GetSecurityGroups()
	c.JSON(http.StatusOK, status)
}

func newGetSecurityGroupHandler(sec helper.SecurityGroupManager) Handler {
	return &getSecurityGroup{securityGroup: sec}
}

type getConfig struct {
	daemon *daemon
}

func (g *getConfig) Handle(c *gin.Context) {
	c.JSON(http.StatusOK, g.daemon.cfg)
}

func newGetConfigHandler(d *daemon) Handler {
	return &getConfig{daemon: d}
}

type getInstanceLimit struct {
	limit helper.InstanceLimitManager
}

func (l *getInstanceLimit) Handle(c *gin.Context) {
	limit := l.limit.GetLimit()
	c.JSON(http.StatusOK, limit.InstanceLimitsAttr)
}

func newInstanceLimitHandler(limit helper.InstanceLimitManager) Handler {
	return &getInstanceLimit{
		limit: limit,
	}
}
