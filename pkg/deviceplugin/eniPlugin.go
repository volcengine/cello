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
	"net"
	"path"
	"time"

	"google.golang.org/grpc"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

// ENIDevicePlugin implements the Kubernetes DevicePlugin API for ENI and IP.
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
	}
}

// GetDevicePluginOptions returns options that ENI devices support.
func (plugin *ENIDevicePlugin) GetDevicePluginOptions(_ context.Context, _ *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

// ListAndWatch returns ENI devices list.
func (plugin *ENIDevicePlugin) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	count := plugin.count

	sendResponse := func(count int, s pluginapi.DevicePlugin_ListAndWatchServer) error {
		res := make([]*pluginapi.Device, count)
		for i := 0; i < count; i++ {
			res[i] = &pluginapi.Device{
				ID:     fmt.Sprintf("%v-%d", plugin.resourceName, i),
				Health: pluginapi.Healthy,
			}
		}

		resp := &pluginapi.ListAndWatchResponse{
			Devices: res,
		}
		err := stream.Send(resp)
		log.InfoS("Report resources", "resourceName", plugin.resourceName, "count", count)
		if err != nil {
			log.ErrorS(err, "Send devices error")
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
			count = plugin.count
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		// Send	new list when resource count changed
		case plugin.count = <-plugin.updateSignal:
			count = plugin.count
			err := sendResponse(count, stream)
			if err != nil {
				return err
			}
		case <-plugin.ctx.Done():
			return plugin.ctx.Err()
		}
	}
}

// Allocate does nothing, here we only return a void response.
func (plugin *ENIDevicePlugin) Allocate(_ context.Context, request *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := pluginapi.AllocateResponse{
		ContainerResponses: []*pluginapi.ContainerAllocateResponse{},
	}

	for range request.GetContainerRequests() {
		resp.ContainerResponses = append(
			resp.ContainerResponses,
			&pluginapi.ContainerAllocateResponse{},
		)
	}

	return &resp, nil
}

// PreStartContainer is not supported by this plugin.
func (plugin *ENIDevicePlugin) PreStartContainer(_ context.Context, _ *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

// GetPreferredAllocation is not supported by this plugin.
func (plugin *ENIDevicePlugin) GetPreferredAllocation(_ context.Context, _ *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}

// Endpoint returns the path of grpc UDS endpoint
func (plugin *ENIDevicePlugin) Endpoint() string {
	return plugin.apiEndPoint
}

func (plugin *ENIDevicePlugin) ResourceName() string {
	return plugin.resourceName
}

func (plugin *ENIDevicePlugin) Update(count int) {
	if count == plugin.count {
		return
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case plugin.updateSignal <- count:
		return
	case <-t.C:
		plugin.count = count
	case <-plugin.updateSignal:
		plugin.updateSignal <- count
		plugin.count = count
		log.ErrorS(nil, "Failed to update resource count", "count", count)
		return
	}
}

func (plugin *ENIDevicePlugin) Serve(ctx context.Context, lis net.Listener) error {
	plugin.ctx = ctx
	if plugin.server != nil {
		plugin.server.Stop()
		plugin.server = nil
	}
	plugin.server = grpc.NewServer()

	pluginapi.RegisterDevicePluginServer(plugin.server, plugin)

	err := plugin.server.Serve(lis)
	if err != nil {
		return err
	}

	return nil
}

func (plugin *ENIDevicePlugin) Stop() {
	if plugin.server != nil {
		plugin.server.Stop()
		plugin.server = nil
	}
}
