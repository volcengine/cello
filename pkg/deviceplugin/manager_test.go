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

package deviceplugin_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"

	"github.com/volcengine/cello/pkg/deviceplugin"
	"github.com/volcengine/cello/pkg/deviceplugin/mock"
)

const (
	tmpPath = "/tmp/device-plugin/test/"
)

func TestPluginManager_UseSharedENI(t *testing.T) {
	setupEnv()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := mock.NewMockKubelet(deviceplugin.DevicePluginPath)
	err := client.StartServer(ctx)
	assert.NoError(t, err)

	manager := deviceplugin.NewResourcePluginManager(
		deviceplugin.NewENIDevicePlugin(deviceplugin.ENIIPResourceName, 5))
	assert.NotNil(t, manager.Plugin(deviceplugin.ENIIPResourceName))
	defer manager.Stop()

	err = manager.Serve(ctx)
	assert.NoError(t, err)
	assert.True(t, client.Registered(deviceplugin.VolcNameSpace+deviceplugin.ENIIPResourceName))

	// Test get options.
	var pluginOption *pluginapi.DevicePluginOptions
	pluginOption, err = client.Res[deviceplugin.VolcNameSpace+deviceplugin.ENIIPResourceName].
		Client.GetDevicePluginOptions(ctx, &pluginapi.Empty{})
	assert.NotNil(t, pluginOption)
	assert.NoError(t, err)
	wantOptions, err := manager.Plugin(deviceplugin.ENIIPResourceName).GetDevicePluginOptions(
		ctx, &pluginapi.Empty{})
	assert.NoError(t, err)
	assert.Equal(t, wantOptions.String(), pluginOption.String())

	// Test list and watch.
	watch := client.Res[deviceplugin.VolcNameSpace+deviceplugin.ENIIPResourceName].Watcher
	recv, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(recv.Devices))
	err = manager.Update(deviceplugin.ENIIPResourceName, 3)
	assert.NoError(t, err)
	recv, err = watch.Recv()
	assert.Equal(t, 3, len(recv.Devices))

	// Test restart.
	err = client.Stop()
	assert.NoError(t, err)
	time.Sleep(time.Second)
	_ = manager.Update(deviceplugin.ENIIPResourceName, 4)
	_ = manager.Update(deviceplugin.ENIIPResourceName, 6)
	err = client.StartServer(ctx)
	assert.NoError(t, err)
	maxRetries := 5
	for j := 0; j <= maxRetries; j++ {
		time.Sleep(time.Second)
		if client.Registered(deviceplugin.VolcNameSpace + deviceplugin.ENIIPResourceName) {
			break
		}
		if j == maxRetries {
			t.FailNow()
		}
	}
	watch = client.Res[deviceplugin.VolcNameSpace+deviceplugin.ENIIPResourceName].Watcher
	recv, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 4, len(recv.Devices))
	recv, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 6, len(recv.Devices))

	manager.Stop()
	assert.NoFileExists(t, manager.Plugin(deviceplugin.ENIIPResourceName).Endpoint())
}

func TestPluginManager_UseBranchENI(t *testing.T) {
	setupEnv()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := mock.NewMockKubelet(deviceplugin.DevicePluginPath)
	err := client.StartServer(ctx)
	assert.NoError(t, err)

	manager := deviceplugin.NewResourcePluginManager(
		deviceplugin.NewENIDevicePlugin(deviceplugin.ENIResourceName, 5),
		deviceplugin.NewENIDevicePlugin(deviceplugin.BranchENIResourceName, 3))
	assert.NotNil(t, manager.Plugin(deviceplugin.ENIResourceName))
	defer manager.Stop()

	stopCh := make(chan struct{})
	err = manager.Serve(ctx)
	assert.NoError(t, err)

	maxRetries := 5
	for j := 0; j <= maxRetries; j++ {
		time.Sleep(time.Second)
		if client.Registered(deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName) &&
			client.Registered(deviceplugin.VolcNameSpace+deviceplugin.BranchENIResourceName) {
			break
		}
		if j == maxRetries {
			t.FailNow()
		}
	}

	// Test get options.
	var pluginOption *pluginapi.DevicePluginOptions
	pluginOption, err = client.Res[deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName].
		Client.GetDevicePluginOptions(ctx, &pluginapi.Empty{})
	assert.NotNil(t, pluginOption)
	assert.NoError(t, err)
	wantOptions, err := manager.Plugin(deviceplugin.ENIResourceName).GetDevicePluginOptions(
		ctx, &pluginapi.Empty{})
	assert.NoError(t, err)
	assert.Equal(t, wantOptions.String(), pluginOption.String())

	// Test list and watch.
	watch := client.Res[deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName].Watcher
	recv, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(recv.Devices))
	err = manager.Update(deviceplugin.ENIResourceName, 3)
	assert.NoError(t, err)
	recv, err = watch.Recv()
	assert.Equal(t, 3, len(recv.Devices))

	// Test restart.
	_ = client.Stop()
	time.Sleep(time.Second)
	_ = manager.Update(deviceplugin.ENIResourceName, 4)
	_ = manager.Update(deviceplugin.ENIResourceName, 6)
	err = client.StartServer(ctx)
	assert.NoError(t, err)
	for j := 0; j <= maxRetries; j++ {
		time.Sleep(time.Second)
		if client.Registered(deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName) &&
			client.Registered(deviceplugin.VolcNameSpace+deviceplugin.BranchENIResourceName) {
			break
		}
		if j == maxRetries {
			t.FailNow()
		}
	}
	watch = client.Res[deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName].Watcher
	recv, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 4, len(recv.Devices))
	recv, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 6, len(recv.Devices))

	close(stopCh)
	// Close the channel will not clean up socket file.
	assert.FileExists(t, manager.Plugin(deviceplugin.ENIResourceName).Endpoint())
}

func TestPluginManager_Restart(t *testing.T) {
	setupEnv()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := mock.NewMockKubelet(deviceplugin.DevicePluginPath)
	err := client.StartServer(ctx)
	assert.NoError(t, err)
	defer client.Stop()

	manager := deviceplugin.NewResourcePluginManager(
		deviceplugin.NewENIDevicePlugin(deviceplugin.ENIResourceName, 5),
		deviceplugin.NewENIDevicePlugin(deviceplugin.BranchENIResourceName, 3))
	assert.NotNil(t, manager.Plugin(deviceplugin.ENIResourceName))

	err = client.Stop()
	assert.NoError(t, err)

	err = manager.Serve(ctx)
	assert.Error(t, err)
	defer manager.Stop()

	err = client.StartServer(ctx)
	assert.NoError(t, err)
	err = manager.Serve(ctx)
	assert.NoError(t, err)
	for i := 0; i < 10; i++ {
		// Test restart.
		err = client.Stop()
		assert.NoError(t, err)
		err = client.StartServer(ctx)
		assert.NoError(t, err)
		maxRetries := 5
		for j := 0; j <= maxRetries; j++ {
			time.Sleep(time.Second)
			if client.Registered(deviceplugin.VolcNameSpace+deviceplugin.ENIResourceName) &&
				client.Registered(deviceplugin.VolcNameSpace+deviceplugin.BranchENIResourceName) {
				break
			}
			if j == maxRetries {
				t.FailNow()
			}
		}
	}
}

func setupEnv() {
	deviceplugin.DevicePluginPath = tmpPath
	_ = os.MkdirAll(deviceplugin.DevicePluginPath, os.ModePerm)
	deviceplugin.KubeletSocket = deviceplugin.DevicePluginPath + "kubelet.sock"
}
