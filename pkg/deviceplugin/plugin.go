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
	"context"
	"fmt"
	"path"
	"time"

	"google.golang.org/grpc"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const period = time.Minute * 3

// ResourceName.
const (
	// VolcNameSpace is a VKE prifix.
	VolcNameSpace = "vke.volcengine.com/"
	// ENIResourceName indicates exclusive ENI resource name.
	ENIResourceName = VolcNameSpace + "eni"
	// ENIIPResourceName indicates shared ENI ip addresses resource name.
	ENIIPResourceName = VolcNameSpace + "eni-ip"
	// BranchENIResourceName indicates truck ENI.
	BranchENIResourceName = VolcNameSpace + "branch-eni"
)

type ENIType int

const (
	Exclusive = iota
	Shared
	Trunk
)

var DevicePluginPath = pluginapi.DevicePluginPath
var KubeletSocket = DevicePluginPath + "kubelet.sock"

type resource struct {
	updateSignal chan struct{}
	count        int
}

// ENIDevicePlugin implements the Kubernetes devices device deviceplugin API.
type ENIDevicePlugin struct {
	ENIType
	name     string
	endPoint string
	server   *grpc.Server
	res      *resource
	ctx      context.Context
	listFunc func() int
}

// NewENIDevicePlugin creates a new ENIDevicePlugin.
func NewENIDevicePlugin(t ENIType, res *resource, list func() int) *ENIDevicePlugin {
	switch t {
	case Exclusive:
		return &ENIDevicePlugin{
			ENIType:  Exclusive,
			name:     ENIResourceName,
			endPoint: path.Join(DevicePluginPath, "eni.sock"),
			res:      res,
			listFunc: list,
		}
	case Shared:
		return &ENIDevicePlugin{
			ENIType:  Shared,
			name:     ENIIPResourceName,
			endPoint: path.Join(DevicePluginPath, "eni-ip.sock"),
			res:      res,
			listFunc: list,
		}
	case Trunk:
		return &ENIDevicePlugin{
			ENIType:  Trunk,
			name:     BranchENIResourceName,
			endPoint: path.Join(DevicePluginPath, "branch-eni.sock"),
			res:      res,
			listFunc: list,
		}
	}
	return nil
}

// GetDevicePluginOptions returns options that ENI devices support.
func (eniPlugin ENIDevicePlugin) GetDevicePluginOptions(_ context.Context, _ *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

// ListAndWatch returns ENI devices list.
func (eniPlugin ENIDevicePlugin) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	count := eniPlugin.listFunc()

	sendResponse := func(count int, s pluginapi.DevicePlugin_ListAndWatchServer) error {
		enis := make([]*pluginapi.Device, count)
		for i := 0; i < count; i++ {
			enis[i] = &pluginapi.Device{
				ID:     fmt.Sprintf("%v-%d", eniPlugin.name, i),
				Health: pluginapi.Healthy,
			}
		}

		resp := &pluginapi.ListAndWatchResponse{
			Devices: enis,
		}
		err := stream.Send(resp)
		log.Infof("Report resources: %v of %v", eniPlugin.name, count)
		if err != nil {
			log.Errorf("Send devices error: %v", err)
			return err
		}
		return nil
	}

	if err := sendResponse(count, stream); err != nil {
		return err
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			count = eniPlugin.listFunc()
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		// Send	new list when resource count changed
		case <-eniPlugin.res.updateSignal:
			count = eniPlugin.res.count
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		case <-eniPlugin.ctx.Done():
			return nil
		}
	}
}

// Allocate does nothing, here we only return a void response.
func (eniPlugin ENIDevicePlugin) Allocate(_ context.Context, request *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := pluginapi.AllocateResponse{
		ContainerResponses: []*pluginapi.ContainerAllocateResponse{},
	}

	for range request.GetContainerRequests() {
		resp.ContainerResponses = append(resp.ContainerResponses,
			&pluginapi.ContainerAllocateResponse{},
		)
	}

	return &resp, nil
}

// PreStartContainer is not supported by this plugin.
func (eniPlugin ENIDevicePlugin) PreStartContainer(_ context.Context, _ *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

// GetPreferredAllocation is not supported by this plugin.
func (eniPlugin ENIDevicePlugin) GetPreferredAllocation(_ context.Context, _ *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}
