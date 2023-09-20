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

package deviceplugin

import (
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

// ResourcesName.
const (
	// VolcNameSpace is the resource namespace for VKE volcengine.
	VolcNameSpace = "vke.volcengine.com/"
	// ENIResourceName indicates exclusive ENI resource resourceName.
	ENIResourceName = "eni"
	// ENIIPResourceName indicates shared ENI ip addresses resource resourceName.
	ENIIPResourceName = "eni-ip"
	// BranchENIResourceName indicates truck ENI.
	BranchENIResourceName = "branch-eni"
)

const reportPeriod = time.Minute * 3

var (
	DevicePluginPath = pluginapi.DevicePluginPath
	KubeletSocket    = DevicePluginPath + "kubelet.sock"
)

// Manager is the interface of device plugin manager.
type Manager interface {
	AddPlugin(plugin Plugin)
	Plugin(resourceName string) Plugin
	Serve(stopCh chan struct{}) error
	Stop()
	Update(resourceName string, count int) error
}

// Plugin is the interface for generic device plugin which can be managed by Manager.
type Plugin interface {
	pluginapi.DevicePluginServer
	Endpoint() string
	ResourceName() string
	Server() *grpc.Server
	ResetServer()
	SetContext(ctx context.Context)
	Update(count int)
}
