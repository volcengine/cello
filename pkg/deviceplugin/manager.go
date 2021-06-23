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
	"net"
	"os"
	"path"
	"time"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"

	"github.com/volcengine/cello/pkg/deviceplugin/mock"
	"github.com/volcengine/cello/pkg/utils/logger"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "deviceplugin"})

// Manager is the interface of device plugin manager.
type Manager interface {
	Serve(stopCh chan struct{}) error
	Stop()
	Update(count int)
}

// PluginManager manages all device plugins.
type PluginManager struct {
	plugins []*ENIDevicePlugin
	res     *resource
	cancel  context.CancelFunc
	ctx     context.Context
}

type PluginManagerOption struct {
	useExclusiveENI bool
	useSharedENI    bool
	useBranchENI    bool
	ctx             context.Context
	eniLister       func() int
	eniIPLister     func() int
	branchENILister func() int
	dryRun          bool
}

// NewPluginManagerWithOptions creates a new PluginManager with given options.
func NewPluginManagerWithOptions(option *PluginManagerOption) *PluginManager {
	var ctx context.Context
	var cancel context.CancelFunc
	if option.ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(option.ctx)
	}
	manager := PluginManager{
		plugins: []*ENIDevicePlugin{},
		cancel:  cancel,
		res:     &resource{},
	}
	if option.useExclusiveENI {
		manager.res.updateSignal = make(chan struct{})
		manager.plugins = append(manager.plugins, NewENIDevicePlugin(Exclusive, manager.res, option.eniLister))
		manager.ctx = ctx
	}
	if option.useSharedENI {
		manager.res.updateSignal = make(chan struct{})
		manager.plugins = append(manager.plugins, NewENIDevicePlugin(Shared, manager.res, option.eniIPLister))
		manager.ctx = ctx
	}

	if option.useBranchENI {
		resNumCh := resource{
			updateSignal: make(chan struct{}),
		}
		manager.plugins = append(manager.plugins, NewENIDevicePlugin(Trunk, &resNumCh, option.branchENILister))
		manager.ctx = ctx
	}

	return &manager
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
			Endpoint:     path.Base(plugin.endPoint),
			ResourceName: plugin.name,
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
					return
				}
				if event.Name == KubeletSocket && event.Has(fsnotify.Create) {
					log.Infof(" %s created, restarting.", pluginapi.KubeletSocket)
					manager.Stop()
					manager.ctx, manager.cancel = context.WithCancel(context.Background())
					_ = manager.start()
					err = manager.register()
					if err != nil {
						log.Errorf("Register failed after kubelet restart", err)
					}
					if err != nil {
						log.Errorf("register failed after kubelet restart")
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
func (manager *PluginManager) Update(count int) {
	go func() {
		t := time.NewTimer(5 * time.Second)
		manager.res.count = count
		select {
		case manager.res.updateSignal <- struct{}{}:
			return
		case <-t.C:
			log.Errorf("Failed to update resource count: %v ", count)
			return
		}
	}()
}

// start will boot grpc service and listen on /var/lib/kubelet/device-plugin/<res>.sock.
func (manager *PluginManager) start() error {
	if err := manager.cleanUp(); err != nil {
		return err
	}
	for _, eniPlugin := range manager.plugins {
		sock, err := net.Listen("unix", eniPlugin.endPoint)
		if err != nil {
			return err
		}
		eniPlugin.server = grpc.NewServer()
		eniPlugin.ctx = manager.ctx
		pluginapi.RegisterDevicePluginServer(eniPlugin.server, eniPlugin)

		go func() {
			err := eniPlugin.server.Serve(sock)
			if err != nil {
				log.Errorf("Failed to serve deviceplugin grpc server.")
			}
		}()

		conn, err := dailUnix(manager.ctx, eniPlugin.endPoint)
		if err != nil {
			return err
		}
		err = conn.Close()
		if err != nil {
			return err
		}
		log.Infof("Start device plugin for %v", eniPlugin.name)
	}
	return nil
}

// stop will stop all grpc server and delete endpoints.
func (manager *PluginManager) stop() {
	manager.cancel()
	for _, eniPlugin := range manager.plugins {
		if eniPlugin.server == nil {
			return
		}
		eniPlugin.server.Stop()
		eniPlugin.server = nil
	}
}

// cleanUp delete all resource.
func (manager *PluginManager) cleanUp() error {
	for _, res := range manager.plugins {
		if err := os.Remove(res.endPoint); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func NewPluginManagerOption() *PluginManagerOption {
	return &PluginManagerOption{}
}

func (option *PluginManagerOption) WithDryRun() *PluginManagerOption {
	option.dryRun = true
	return option
}

func (option *PluginManagerOption) UseExclusiveENI() *PluginManagerOption {
	option.useExclusiveENI = true
	return option
}

func (option *PluginManagerOption) WithENILister(lister func() int) *PluginManagerOption {
	option.eniLister = lister
	return option
}

func (option *PluginManagerOption) UseSharedENI() *PluginManagerOption {
	option.useSharedENI = true
	return option
}

func (option *PluginManagerOption) WithIPLister(lister func() int) *PluginManagerOption {
	option.eniIPLister = lister
	return option
}

func (option *PluginManagerOption) UseBranchENI() *PluginManagerOption {
	option.useBranchENI = true
	return option
}

func (option *PluginManagerOption) WithBranchENILister(lister func() int) *PluginManagerOption {
	option.branchENILister = lister
	return option
}
func (option *PluginManagerOption) WithContext(ctx context.Context) *PluginManagerOption {
	option.ctx = ctx
	return option
}

func (option *PluginManagerOption) BuildManager() Manager {
	if option.dryRun {
		return mock.New()
	}
	return NewPluginManagerWithOptions(option)
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
