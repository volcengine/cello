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
	"os"
	"path"
	"time"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"

	"github.com/volcengine/cello/pkg/utils/logger"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "deviceplugin"})

// PluginManager manages all device plugins.
type PluginManager struct {
	plugins map[string]Plugin
	cancel  context.CancelFunc
	ctx     context.Context
}

func (manager *PluginManager) Plugin(resourceName string) Plugin {
	plugin, _ := manager.plugins[resourceName]
	return plugin
}

func NewResourcePluginManager(ctx context.Context, plugins ...Plugin) *PluginManager {
	mgr := PluginManager{}
	mgr.ctx, mgr.cancel = context.WithCancel(ctx)
	mgr.plugins = make(map[string]Plugin)
	for _, plugin := range plugins {
		plugin.SetContext(mgr.ctx)
		mgr.plugins[plugin.ResourceName()] = plugin
	}
	return &mgr
}

// register registers device plugins grpc endpoints to kubelet
// should be called after start().
func (manager *PluginManager) register() error {
	conn, err := dailUnix(manager.ctx, KubeletSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := pluginapi.NewRegistrationClient(conn)
	for _, plugin := range manager.plugins {
		_, err = client.Register(manager.ctx, &pluginapi.RegisterRequest{
			Version:      pluginapi.Version,
			Endpoint:     path.Base(plugin.Endpoint()),
			ResourceName: path.Join(VolcNameSpace, plugin.ResourceName()),
		})

		if err != nil {
			return err
		}
	}
	return nil
}

// Serve starts device plugins server and watch kubelet restarts.
func (manager *PluginManager) Serve(stopCh chan struct{}) error {
	err := manager.start()
	if err != nil {
		log.Errorf("Device plugin start failed: %v", err)
		return err
	}
	err = manager.register()
	if err != nil {
		log.Errorf("Device plugin register failed: %v", err)
		return err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("Create watcher failed: %v", err)
		return err
	}
	err = watcher.Add(path.Clean(DevicePluginPath))
	if err != nil {
		log.Errorf("Watch kubelet failed")
		return err
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					log.Error("Watch kubelet failed.")
					return
				}
				if event.Name == KubeletSocket && event.Has(fsnotify.Create) {
					log.Infof(" %s created, restarting.", KubeletSocket)
					manager.Stop()
					manager.ctx, manager.cancel = context.WithCancel(context.Background())
					_ = manager.start()
					err = manager.register()
					if err != nil {
						log.Errorf("Register failed after kubelet restart", err)
					}
				} else if event.Name == "kubelet.sock" && event.Op&fsnotify.Remove == fsnotify.Remove {
					log.Infof("Kubelet stopped")
				}

			case err := <-watcher.Errors:
				if err != nil {
					log.Errorf("Watch kubelet failed:v%", err.Error())
				}
			case <-stopCh:
				break
			case <-manager.ctx.Done():
				break
			}
		}
	}()

	return nil
}

// Stop all grpc server and delete endpoints.
func (manager *PluginManager) Stop() {
	manager.stop()
	_ = manager.cleanUp()
}

// Update will emit count to res channel asynchronously.
func (manager *PluginManager) Update(resName string, count int) error {
	plugin, ok := manager.plugins[resName]
	if !ok {
		return fmt.Errorf("plugin not found")
	}
	plugin.Update(count)
	return nil
}

func (manager *PluginManager) AddPlugin(plugin Plugin) {
	plugin.SetContext(manager.ctx)
	manager.plugins[plugin.ResourceName()] = plugin
}

// start will boot grpc service and listen on /var/lib/kubelet/device-plugin/<res>.sock.
func (manager *PluginManager) start() error {
	if err := manager.cleanUp(); err != nil {
		return err
	}
	for _, plugin := range manager.plugins {
		sock, err := net.Listen("unix", plugin.Endpoint())
		if err != nil {
			return err
		}
		plugin.ResetServer()
		plugin.SetContext(manager.ctx)
		pluginapi.RegisterDevicePluginServer(plugin.Server(), plugin)

		go func() {
			err := plugin.Server().Serve(sock)
			if err != nil {
				log.Errorf("Failed to serve deviceplugin grpc server.")
			}
		}()

		conn, err := dailUnix(manager.ctx, plugin.Endpoint())
		if err != nil {
			return err
		}
		err = conn.Close()
		if err != nil {
			return err
		}
		log.Infof("Start device plugin for %v", VolcNameSpace+plugin.ResourceName())
	}
	return nil
}

// stop will stop all grpc server and delete endpoints.
func (manager *PluginManager) stop() {
	manager.cancel()
	for _, eniPlugin := range manager.plugins {
		if eniPlugin.Server() == nil {
			return
		}
		eniPlugin.Server().Stop()
	}
}

// cleanUp delete all resource.
func (manager *PluginManager) cleanUp() error {
	for _, res := range manager.plugins {
		if err := os.Remove(res.Endpoint()); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func dailUnix(ctx context.Context, path string) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, path,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", path, time.Second*10)
		}),
	)
	return conn, err
}
