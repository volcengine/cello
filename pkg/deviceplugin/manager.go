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
}

func (manager *PluginManager) Plugin(resourceName string) Plugin {
	plugin, _ := manager.plugins[resourceName]
	return plugin
}

func NewResourcePluginManager(plugins ...Plugin) *PluginManager {
	mgr := PluginManager{}
	mgr.plugins = make(map[string]Plugin)
	for _, plugin := range plugins {
		mgr.plugins[plugin.ResourceName()] = plugin
	}
	return &mgr
}

// register registers device plugins grpc endpoints to kubelet
// should be called after startPluginServers().
func (manager *PluginManager) register(ctx context.Context) error {
	// grpc.Dial and withBlock option are not recommend
	// see: https://github.com/grpc/grpc-go/blob/master/Documentation/anti-patterns.md.
	conn, err := grpc.NewClient("unix://"+KubeletSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := pluginapi.NewRegistrationClient(conn)
	for _, plugin := range manager.plugins {
		_, err = client.Register(ctx, &pluginapi.RegisterRequest{
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
func (manager *PluginManager) Serve(ctx context.Context) error {
	_, manager.cancel = context.WithCancel(ctx)
	started := false
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.ErrorS(err, "Create watcher failed")
		return err
	}
	err = watcher.Add(path.Clean(DevicePluginPath))
	if err != nil {
		log.ErrorS(err, "Watch kubelet failed")
		return err
	}
	go func() {
		defer watcher.Close()
		for {
			if !started {
				time.Sleep(time.Second)
				continue
			}
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					log.Fatalf("Watch kubelet failed.")
					return
				}
				if event.Name == KubeletSocket && event.Has(fsnotify.Create) {
					log.InfoS("KubeletSocket created, restarting.", "KubeletSocket", KubeletSocket)
					manager.Stop()
					currentCtx, cancel := context.WithCancel(ctx)
					manager.cancel = cancel
					err = manager.startPluginServers(currentCtx)
					if err != nil {
						log.FatalS(err, "Start Servers failed after kubelet restart")
						return
					}
					err = manager.register(currentCtx)
					if err != nil {
						log.FatalS(err, "Register failed after kubelet restart")
						return
					}
				} else if event.Name == "kubelet.sock" && event.Op&fsnotify.Remove == fsnotify.Remove {
					log.InfoS("Kubelet stopped")
				}
			case err := <-watcher.Errors:
				if err != nil {
					log.FatalS(err, "Watch kubelet failed")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	err = manager.startPluginServers(ctx)
	if err != nil {
		log.ErrorS(err, "Device plugin startPluginServers failed")
		return err
	}
	err = manager.register(ctx)
	if err != nil {
		log.ErrorS(err, "Device plugin register failed")
		return err
	}
	started = true
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
	manager.plugins[plugin.ResourceName()] = plugin
}

// startPluginServers will boot grpc service and listen on /var/lib/kubelet/device-plugin/<res>.sock.
func (manager *PluginManager) startPluginServers(ctx context.Context) error {
	if err := manager.cleanUp(); err != nil {
		return err
	}
	for _, plugin := range manager.plugins {
		_ = os.Remove(plugin.Endpoint())
		sock, err := net.Listen("unix", plugin.Endpoint())
		if err != nil {
			return err
		}
		p := plugin

		go func() {
			err = p.Serve(ctx, sock)
			if err != nil {
				log.ErrorS(err, "Failed to serve deviceplugin grpc server.")
			}
		}()
		// grpc.Dial and withBlock option are not recommend
		// see: https://github.com/grpc/grpc-go/blob/master/Documentation/anti-patterns.md.
		conn, err := grpc.NewClient("unix://"+KubeletSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		err = conn.Close()
		if err != nil {
			return err
		}
		log.InfoS("Start device plugin", "ResourceName", VolcNameSpace+plugin.ResourceName())
	}
	return nil
}

// stop will stop all grpc server and delete endpoints.
func (manager *PluginManager) stop() {
	manager.cancel()
	for _, eniPlugin := range manager.plugins {
		eniPlugin.Stop()
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
