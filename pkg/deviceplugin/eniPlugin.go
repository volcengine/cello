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

// ENIDevicePlugin implements the Kubernetes devices device deviceplugin API.
type ENIDevicePlugin struct {
	resourceName string
	apiEndPoint  string
	count        int
	updateSignal chan int
	server       *grpc.Server
	ctx          context.Context
}

// NewENIDevicePlugin creates a new ENIDevicePlugin.
func NewENIDevicePlugin(resName string, initCount int) *ENIDevicePlugin {
	return &ENIDevicePlugin{
		resourceName: resName,
		apiEndPoint:  path.Join(DevicePluginPath, resName+".sock"),
		count:        initCount,
		updateSignal: make(chan int, 1),
		server:       grpc.NewServer(),
		ctx:          context.TODO(),
	}
}

// GetDevicePluginOptions returns options that ENI devices support.
func (eniPlugin *ENIDevicePlugin) GetDevicePluginOptions(_ context.Context, _ *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

// ListAndWatch returns ENI devices list.
func (eniPlugin *ENIDevicePlugin) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	count := eniPlugin.count

	sendResponse := func(count int, s pluginapi.DevicePlugin_ListAndWatchServer) error {
		res := make([]*pluginapi.Device, count)
		for i := 0; i < count; i++ {
			res[i] = &pluginapi.Device{
				ID:     fmt.Sprintf("%v-%d", eniPlugin.resourceName, i),
				Health: pluginapi.Healthy,
			}
		}

		resp := &pluginapi.ListAndWatchResponse{
			Devices: res,
		}
		err := stream.Send(resp)
		log.Infof("Report resources: %v of %v", eniPlugin.resourceName, count)
		if err != nil {
			log.Errorf("Send devices error: %v", err)
			return err
		}
		return nil
	}

	if err := sendResponse(count, stream); err != nil {
		return err
	}
	ticker := time.NewTicker(reportPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			count = eniPlugin.count
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		// Send	new list when resource count changed
		case eniPlugin.count = <-eniPlugin.updateSignal:
			count = eniPlugin.count
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
func (eniPlugin *ENIDevicePlugin) Allocate(_ context.Context, request *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
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
func (eniPlugin *ENIDevicePlugin) PreStartContainer(_ context.Context, _ *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

// GetPreferredAllocation is not supported by this plugin.
func (eniPlugin *ENIDevicePlugin) GetPreferredAllocation(_ context.Context, _ *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}

// Endpoint returns the path of grpc UDS endpoint
func (eniPlugin *ENIDevicePlugin) Endpoint() string {
	return eniPlugin.apiEndPoint
}

func (eniPlugin *ENIDevicePlugin) ResourceName() string {
	return eniPlugin.resourceName
}

func (eniPlugin *ENIDevicePlugin) Server() *grpc.Server {
	return eniPlugin.server
}

func (eniPlugin *ENIDevicePlugin) ResetServer() {
	eniPlugin.server = grpc.NewServer()
}

func (eniPlugin *ENIDevicePlugin) SetContext(ctx context.Context) {
	eniPlugin.ctx = ctx
}

func (eniPlugin *ENIDevicePlugin) Update(count int) {
	if count == eniPlugin.count {
		return
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case eniPlugin.updateSignal <- count:
		return
	case <-t.C:
		eniPlugin.count = count
	case <-eniPlugin.updateSignal:
		eniPlugin.updateSignal <- count
		eniPlugin.count = count
		log.Errorf("Failed to update resource count: %v ", count)
		return
	}
}
