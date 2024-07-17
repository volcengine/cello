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

package mock

import (
	"context"
	"net"
	"os"
	"path"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

// Kubelet MockClient is a mock RPC client of kubelet for testing purpose.
type Kubelet struct {
	srv              *grpc.Server
	sock             net.Listener
	Res              map[string]*deviceResource
	devicepluginPath string
	registered       map[string]struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	sync.Mutex
}

type deviceResource struct {
	name     string
	endpoint string
	Client   pluginapi.DevicePluginClient
	Watcher  pluginapi.DevicePlugin_ListAndWatchClient
}

func NewMockKubelet(devicepluginPath string) *Kubelet {
	return &Kubelet{
		devicepluginPath: devicepluginPath,
		srv:              nil,
		sock:             nil,
		Res:              make(map[string]*deviceResource),
		registered:       make(map[string]struct{}),
	}
}

func (m *Kubelet) Register(_ context.Context, request *pluginapi.RegisterRequest) (*pluginapi.Empty, error) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.Res[request.ResourceName] = &deviceResource{
		name:     request.ResourceName,
		endpoint: request.Endpoint,
	}
	m.registered[request.ResourceName] = struct{}{}
	conn, err := grpc.DialContext(m.ctx, path.Join(m.devicepluginPath, request.Endpoint),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr, err := net.ResolveUnixAddr("unix", addr)
			if err != nil {
				return nil, err
			}
			return net.DialUnix("unix", nil, socketAddr)
		}))
	if err != nil {
		return &pluginapi.Empty{}, err
	}
	m.Res[request.ResourceName].Client = pluginapi.NewDevicePluginClient(conn)
	m.Res[request.ResourceName].Watcher, _ = m.Res[request.ResourceName].Client.ListAndWatch(m.ctx, &pluginapi.Empty{})

	return &pluginapi.Empty{}, nil
}

func (m *Kubelet) StartServer(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	kubeletSock := path.Join(m.devicepluginPath, "kubelet.sock")
	socket, err := net.Listen("unix", kubeletSock)
	if err != nil {
		_ = os.Remove(kubeletSock)
		socket, err = net.Listen("unix", kubeletSock)
	}
	if err != nil {
		return err
	}

	m.srv = grpc.NewServer()
	pluginapi.RegisterRegistrationServer(m.srv, m)
	go m.srv.Serve(socket)
	if err != nil {
		return err
	}

	_, err = grpc.DialContext(m.ctx, kubeletSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr, err := net.ResolveUnixAddr("unix", addr)
			if err != nil {
				return nil, err
			}
			return net.DialUnix("unix", nil, socketAddr)
		}))

	return err
}

func (m *Kubelet) Stop() error {
	m.registered = make(map[string]struct{})
	m.cancel()
	m.srv.Stop()

	entries, err := os.ReadDir(m.devicepluginPath)
	if err != nil {
		return err
	}

	for _, e := range entries {
		err = os.RemoveAll(path.Join(m.devicepluginPath, e.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Kubelet) Registered(name string) bool {
	m.Mutex.Lock()
	_, ok := m.registered[name]
	m.Mutex.Unlock()
	return ok
}
