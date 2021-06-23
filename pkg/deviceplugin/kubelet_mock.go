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
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

// Kubelet MockClient is a mock RPC client of kubelet for testing purpose.
type Kubelet struct {
	srv        *grpc.Server
	sock       net.Listener
	Res        []deviceResource
	registered bool
	sync.Mutex
}

type deviceResource struct {
	name     string
	endpoint string
	Client   pluginapi.DevicePluginClient
	Watcher  pluginapi.DevicePlugin_ListAndWatchClient
}

func NewMockClient() *Kubelet {
	return &Kubelet{
		srv:  nil,
		sock: nil,
		Res:  make([]deviceResource, 0),
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

	conn, err := grpc.DialContext(context.Background(), path.Join(DevicePluginPath, request.Endpoint),
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
	m.Res[len(m.Res)-1].Watcher, _ = m.Res[0].Client.ListAndWatch(context.Background(), &pluginapi.Empty{})

	return &pluginapi.Empty{}, nil
}

func (m *Kubelet) StartServer() error {
	socket, err := net.Listen("unix", KubeletSocket)
	if err != nil {
		_ = os.Remove(KubeletSocket)
		socket, err = net.Listen("unix", KubeletSocket)
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

	_, err = grpc.DialContext(context.Background(), path.Join(DevicePluginPath, KubeletSocket),
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
	m.srv.Stop()
	m.srv = nil
	err := os.Remove(KubeletSocket)
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
