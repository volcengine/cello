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

package client

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"

	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/cni/types"
)

const (
	defaultKubeletSocket       = "kubelet"        // which is defined in k8s.io/kubernetes/pkg/kubelet/apis/podresources
	defaultPodResourcesMaxSize = 1024 * 1024 * 16 // 16 Mb
	defaultPodResourcesPath    = "/var/lib/kubelet/pod-resources"
	unixProtocol               = "unix"
)

// localEndpoint returns the full path to a unix socket at the given endpoint
// which is in k8s.io/kubernetes/pkg/kubelet/util.
func localEndpoint(path string) *url.URL {
	return &url.URL{
		Scheme: unixProtocol,
		Path:   path + ".sock",
	}
}

// GetResourceClient returns an instance of ResourceClient interface initialized with Pod resource information.
func GetResourceClient(kubeletSocket string) (types.ResourceClient, error) {
	kubeletSocketURL := localEndpoint(filepath.Join(defaultPodResourcesPath, defaultKubeletSocket))

	if kubeletSocket != "" {
		kubeletSocketURL = &url.URL{
			Scheme: unixProtocol,
			Path:   kubeletSocket,
		}
	}
	// If Kubelet resource API endpoint exist use that by default
	// Or else fallback with checkpoint file
	if hasKubeletAPIEndpoint(kubeletSocketURL) {
		log.Log.Debugf("GetResourceClient: using Kubelet resource API endpoint")
		return getKubeletClient(kubeletSocketURL)
	}

	return nil, fmt.Errorf("GetResourceClient: kubelet resource API endpiont not found")
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, unixProtocol, addr)
}

func getKubeletResourceClient(kubeletSocketURL *url.URL, timeout time.Duration) (podresourcesapi.PodResourcesListerClient, *grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, kubeletSocketURL.Path, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dial),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaultPodResourcesMaxSize)))
	if err != nil {
		return nil, nil, fmt.Errorf("error dialing socket %s: %v", kubeletSocketURL.Path, err)
	}
	return podresourcesapi.NewPodResourcesListerClient(conn), conn, nil
}

func getKubeletClient(kubeletSocketURL *url.URL) (types.ResourceClient, error) {
	newClient := &kubeletClient{}

	client, conn, err := getKubeletResourceClient(kubeletSocketURL, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("getKubeletClient: error getting grpc client: %v\n", err)
	}
	defer conn.Close()

	if err := newClient.getPodResources(client); err != nil {
		return nil, fmt.Errorf("getKubeletClient: error getting pod resources from client: %v\n", err)
	}

	return newClient, nil
}

type kubeletClient struct {
	resources []*podresourcesapi.PodResources
}

func (rc *kubeletClient) getPodResources(client podresourcesapi.PodResourcesListerClient) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.List(ctx, &podresourcesapi.ListPodResourcesRequest{})
	if err != nil {
		return fmt.Errorf("getPodResources: failed to list pod resources, %v.Get(_) = _, %v", client, err)
	}

	rc.resources = resp.PodResources

	return nil
}

// GetPodResourceMap returns an instance of a map of Pod ResourceInfo given a (Pod name, namespace) tuple.
func (rc *kubeletClient) GetPodResourceMap(ns, name string) (map[string]*types.ResourceInfo, error) {
	resourceMap := make(map[string]*types.ResourceInfo)

	if name == "" || ns == "" {
		return nil, fmt.Errorf("GetPodResourceMap: Pod name or namespace cannot be empty")
	}

	for _, pr := range rc.resources {
		if pr.Name == name && pr.Namespace == ns {
			for _, cnt := range pr.Containers {
				for _, dev := range cnt.Devices {
					log.Log.Infof("Got device %+v for pod %s/%s", dev, ns, name)
					if rInfo, ok := resourceMap[dev.ResourceName]; ok {
						rInfo.DeviceIDs = append(rInfo.DeviceIDs, dev.DeviceIds...)
					} else {
						resourceMap[dev.ResourceName] = &types.ResourceInfo{DeviceIDs: dev.DeviceIds}
					}
				}
			}
		}
	}
	return resourceMap, nil
}

func hasKubeletAPIEndpoint(url *url.URL) bool {
	// Check for kubelet resource API socket file
	if _, err := os.Stat(url.Path); err != nil {
		log.Log.Debugf("hasKubeletAPIEndpoint: error looking up kubelet resource api socket file: %q", err)
		return false
	}
	return true
}
