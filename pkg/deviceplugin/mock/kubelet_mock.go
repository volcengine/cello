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
	Res              []deviceResource
	devicepluginPath string
	registered       bool
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
	ctx, cancel := context.WithCancel(context.Background())
	return &Kubelet{
		devicepluginPath: devicepluginPath,
		srv:              nil,
		sock:             nil,
		Res:              make([]deviceResource, 0),
		ctx:              ctx,
		cancel:           cancel,
	}
}

func (m *Kubelet) Register(_ context.Context, request *pluginapi.RegisterRequest) (*pluginapi.Empty, error) {
	m.Res = append(m.Res, deviceResource{
		name:     request.ResourceName,
		endpoint: request.Endpoint,
	})
	m.Mutex.Lock()
	m.registered = true
	m.Mutex.Unlock()

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
	m.Res[len(m.Res)-1].Client = pluginapi.NewDevicePluginClient(conn)
	m.Res[len(m.Res)-1].Watcher, _ = m.Res[0].Client.ListAndWatch(m.ctx, &pluginapi.Empty{})

	return &pluginapi.Empty{}, nil
}

func (m *Kubelet) StartServer() error {
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
	m.Res = []deviceResource{}

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
	m.registered = false
	m.cancel()
	m.srv.Stop()
	m.srv = nil
	m.ctx, m.cancel = context.WithCancel(context.Background())
	err := os.Remove(path.Join(m.devicepluginPath, "kubelet.sock"))
	if err != nil {
		return err
	}
	return nil
}

func (m *Kubelet) Registered() bool {
	m.Mutex.Lock()
	hasRegistered := m.registered
	m.Mutex.Unlock()
	return hasRegistered
}
