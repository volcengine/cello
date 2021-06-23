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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	tmpPath = "/tmp/device-plugin/test/"
)

func TestPluginManager_UseSharedENI(t *testing.T) {
	setupEnv()
	client := NewMockClient()
	err := client.StartServer()
	assert.NoError(t, err)

	option := NewPluginManagerOption().UseSharedENI().WithIPLister(func() int {
		return 5
	}).WithContext(context.Background())
	manager := NewPluginManagerWithOptions(option)
	defer manager.cleanUp()

	stopCh := make(chan struct{})
	err = manager.Serve(stopCh)
	assert.NoError(t, err)

	// Test get options.
	var pluginOption *pluginapi.DevicePluginOptions
	pluginOption, err = client.Res[0].Client.GetDevicePluginOptions(context.Background(), &pluginapi.Empty{})
	assert.NoError(t, err)
	wantOptions, err := manager.plugins[0].GetDevicePluginOptions(context.Background(), &pluginapi.Empty{})
	assert.NoError(t, err)
	assert.Equal(t, wantOptions.String(), pluginOption.String())

	// Test list and watch.
	watch := client.Res[0].Watcher
	recv, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(recv.Devices))
	manager.Update(3)
	recv, err = watch.Recv()
	assert.Equal(t, 3, len(recv.Devices))

	// Test restart
	_ = client.Stop()
	assert.NoError(t, err)
	time.Sleep(10 * time.Second)
	err = client.StartServer()
	assert.NoError(t, err)
	time.Sleep(30 * time.Second)
	assert.True(t, client.Registered())

	manager.Stop()
	for _, res := range manager.plugins {
		assert.NoFileExists(t, res.endPoint)
	}
}

func setupEnv() {
	_ = os.MkdirAll(tmpPath, os.ModePerm)
	DevicePluginPath = tmpPath
	KubeletSocket = DevicePluginPath + "kubelet.sock"
}
