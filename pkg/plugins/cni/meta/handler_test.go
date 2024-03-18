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

package meta

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"

	"github.com/volcengine/cello/pkg/plugins/types"
)

var metaConfigList = `
    {
      "cniVersion": "0.3.1",
      "name": "cello-meta",
      "plugins": [
        {
          "type": "cello-cni",
          "capabilities": {
            "bandwidth": true,
            "portMappings": true,
            "io.kubernetes.cri.pod-annotations": true
          },
          "defaultCni": "cello-chainer"
        }
      ]
    }
`
var celloChainningConfigList = `
    {
      "cniVersion": "0.3.1",
      "name": "cello-chainer",
      "plugins": [
        {
          "type": "cello",
          "capabilities": {
            "bandwidth": true,
            "com.volcengine.k8s.network-interface": true
           },
          "redirectToHostCIDRs": ["169.254.0.0/16"]
        }
      ]
    }
`

var podTrunkNetworkAnno = map[string]string{
	"k8s.volcengine.com/pod-networks-definition": `[
		{"namespace": "default", "name":"podnetwork3","traffic":{"routes":{"extraRoutes":[{"dst":"1.1.0.0/16"}]}}}]`,
	"k8s.volcengine.com/pod-networks": `[
	{"name":"podnetwork3","namespace":"default",
		"cniConf":{"name":"cello-chainer","from":"local"},
		"deviceConf":{
			"options":{"trunkMac":"00:16:3e:72:be:e4","vlanID":"1"},"ips":["192.168.10.128/24","2406:d440:10a:ff00:947f:e925:dc9a:bbb8/64"],"mac":"00:16:3e:13:2d:1b"
		},
		"traffic":{
			"routes":{"extraRoutes":[{"dst":"1.1.0.0/16"}]}}}]`,
}

var k8sArgs = &types.K8SArgs{
	CommonArgs:                 cniTypes.CommonArgs{},
	K8S_POD_NAME:               "test-name",
	K8S_POD_NAMESPACE:          "test-namespace",
	K8S_POD_INFRA_CONTAINER_ID: "test-container-id",
	K8S_POD_UID:                "test-pod-uid",
}

func Test_tryLoadDelegateNetConfFromAnno(t *testing.T) {
	type args struct {
		ctx       context.Context
		cniConfig *MetaNetConf
		k8sConfig *types.K8SArgs
	}

	// prepare cni config
	cniConfDir = "/tmp/cello-test"
	err := os.MkdirAll(cniConfDir, 0640)
	assert.NoError(t, err)
	err = os.WriteFile(path.Join(cniConfDir, "10-cello.conflist"), []byte(celloChainningConfigList), 064)
	assert.NoError(t, err)

	var meta cniTypes.NetConfList
	err = json.Unmarshal([]byte(metaConfigList), &meta)
	assert.NoError(t, err)
	var cello MetaDelegateNetConfList
	err = json.Unmarshal([]byte(celloChainningConfigList), &cello)
	assert.NoError(t, err)

	var trunkPodNetwork PodNetwork
	var podNetworks []PodNetwork
	err = json.Unmarshal([]byte(podTrunkNetworkAnno[PodNetworksKey]), &podNetworks)
	assert.NoError(t, err)
	trunkPodNetwork = podNetworks[0]

	tests := []struct {
		name    string
		args    args
		want    []*DelegateNetConf
		wantErr bool
	}{
		{
			name: "Add cello-chainning",
			args: args{
				ctx: context.TODO(),
				cniConfig: &MetaNetConf{
					NetConf:        *meta.Plugins[0],
					DefaultCniType: "cello-chainer",
					RuntimeConfig: RuntimeConfig{
						Bandwidth: &types.BandwidthEntry{EgressRate: 100},
						PodAnnotations: map[string]string{
							"unknown": "unknown",
						},
					},
				},
				k8sConfig: k8sArgs,
			},
			want: []*DelegateNetConf{
				{
					Conf: MetaDelegateNetConf{
						NetConf: cniTypes.NetConf{
							CNIVersion: cello.CNIVersion,
							Name:       cello.Name,
						},
						MetaRequest: MetaRequest{},
					},
					ConfList:       cello,
					Name:           "cello-chainer",
					ConfListPlugin: true,
					PodNetwork: &PodNetwork{
						Namespace: "kube-system",
						Name:      "default",
						CniConf: &CniConf{
							Name: "cello-chainer",
							From: "local",
						},
					},
					MetaRequest: MetaRequest{},
					Index:       0,
					MetaConfig:  MetaConfig{},
					Bytes:       []byte(celloChainningConfigList),
				},
			},
			wantErr: false,
		},
		{
			name: "Add cello-chaining and cello-chainning trunk",
			args: args{
				ctx: context.TODO(),
				cniConfig: &MetaNetConf{
					NetConf:        *meta.Plugins[0],
					DefaultCniType: "cello-chainer",
					RuntimeConfig: RuntimeConfig{
						Bandwidth:      &types.BandwidthEntry{EgressRate: 100},
						PodAnnotations: podTrunkNetworkAnno,
					},
				},
				k8sConfig: k8sArgs,
			},
			want: []*DelegateNetConf{
				{
					Conf: MetaDelegateNetConf{
						NetConf: cniTypes.NetConf{
							CNIVersion: cello.CNIVersion,
							Name:       cello.Name,
						},
						MetaRequest: MetaRequest{},
					},
					ConfList:       cello,
					Name:           "cello-chainer",
					ConfListPlugin: true,
					PodNetwork: &PodNetwork{
						Namespace: "kube-system",
						Name:      "default",
						CniConf: &CniConf{
							Name: "cello-chainer",
							From: "local",
						},
					},
					MetaRequest: MetaRequest{},
					Index:       0,
					MetaConfig:  MetaConfig{},
					Bytes:       []byte(celloChainningConfigList),
				},
				{
					Conf: MetaDelegateNetConf{
						NetConf: cniTypes.NetConf{
							CNIVersion: cello.CNIVersion,
							Name:       cello.Name,
						},
						MetaRequest: MetaRequest{},
					},
					ConfList:       cello,
					Name:           "cello-chainer",
					ConfListPlugin: true,
					PodNetwork:     &trunkPodNetwork,
					MetaRequest:    MetaRequest{},
					Index:          1,
					MetaConfig:     MetaConfig{},
					Bytes:          []byte(celloChainningConfigList),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tryLoadDelegateNetConfFromAnno(tt.args.ctx, tt.args.cniConfig, tt.args.k8sConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("tryLoadDelegateNetConfFromAnno() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equalf(t, tt.want, got, "tryLoadDelegateNetConfFromAnno(%v %v %v)", tt.args.ctx, tt.args.cniConfig, tt.args.k8sConfig)
		})
	}
}

func Test_createCNIRuntimeConf(t *testing.T) {
	type args struct {
		args    *skel.CmdArgs
		k8sArgs *types.K8SArgs
		netConf *MetaNetConf
		d       *DelegateNetConf
		ifName  string
	}

	var meta cniTypes.NetConfList
	err := json.Unmarshal([]byte(metaConfigList), &meta)
	assert.NoError(t, err)

	var cello MetaDelegateNetConfList
	err = json.Unmarshal([]byte(celloChainningConfigList), &cello)
	assert.NoError(t, err)

	var trunkPodNetwork PodNetwork
	var podNetworks []PodNetwork
	err = json.Unmarshal([]byte(podTrunkNetworkAnno[PodNetworksKey]), &podNetworks)
	assert.NoError(t, err)
	trunkPodNetwork = podNetworks[0]

	tests := []struct {
		name    string
		args    args
		want    *libcni.RuntimeConf
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Add vpc cni",
			args: args{
				args: &skel.CmdArgs{
					ContainerID: "test-container-id",
					Netns:       "test-netns",
				},
				k8sArgs: k8sArgs,
				netConf: &MetaNetConf{
					NetConf:        *meta.Plugins[0],
					DefaultCniType: "cello-chainer",
					RuntimeConfig: RuntimeConfig{
						Bandwidth: &types.BandwidthEntry{EgressRate: 100},
					},
				},
				d: &DelegateNetConf{
					ConfList:       cello,
					Name:           "cello-chainer",
					ConfListPlugin: true,
					PodNetwork: &PodNetwork{
						Namespace: "kube-system",
						Name:      "default",
						CniConf: &CniConf{
							Name: "cello-chainer",
							From: "local",
						},
					},
					Index: 0,
					Bytes: []byte(celloChainningConfigList),
				},
				ifName: "eth0",
			},
			want: &libcni.RuntimeConf{
				ContainerID: "test-container-id",
				NetNS:       "test-netns",
				IfName:      "eth0",
				Args: [][2]string{
					{"IgnoreUnknown", "true"},
					{"K8S_POD_NAMESPACE", string(k8sArgs.K8S_POD_NAMESPACE)},
					{"K8S_POD_NAME", string(k8sArgs.K8S_POD_NAME)},
					{"K8S_POD_INFRA_CONTAINER_ID", string(k8sArgs.K8S_POD_INFRA_CONTAINER_ID)},
					{"K8S_POD_UID", string(k8sArgs.K8S_POD_UID)},
				},
				CapabilityArgs: map[string]interface{}{
					"bandwidth": &types.BandwidthEntry{EgressRate: 100},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "Add trunk",
			args: args{
				args: &skel.CmdArgs{
					ContainerID: "test-container-id",
					Netns:       "test-netns",
				},
				k8sArgs: k8sArgs,
				netConf: &MetaNetConf{
					NetConf:        *meta.Plugins[0],
					DefaultCniType: "cello-chainer",
					RuntimeConfig: RuntimeConfig{
						Bandwidth: &types.BandwidthEntry{EgressRate: 100},
					},
				},
				d: &DelegateNetConf{
					ConfList:       cello,
					Name:           "cello-chainer",
					ConfListPlugin: true,
					PodNetwork:     &trunkPodNetwork,
					Index:          1,
					Bytes:          []byte(celloChainningConfigList),
				},
				ifName: "eth1",
			},
			want: &libcni.RuntimeConf{
				ContainerID: "test-container-id",
				NetNS:       "test-netns",
				IfName:      "eth1",
				Args: [][2]string{
					{"IgnoreUnknown", "true"},
					{"K8S_POD_NAMESPACE", string(k8sArgs.K8S_POD_NAMESPACE)},
					{"K8S_POD_NAME", string(k8sArgs.K8S_POD_NAME)},
					{"K8S_POD_INFRA_CONTAINER_ID", string(k8sArgs.K8S_POD_INFRA_CONTAINER_ID)},
					{"K8S_POD_UID", string(k8sArgs.K8S_POD_UID)},
				},
				CapabilityArgs: map[string]interface{}{
					"ips": []*ip.IP{
						ip.ParseIP("192.168.10.128/24"),
						ip.ParseIP("2406:d440:10a:ff00:947f:e925:dc9a:bbb8/64"),
					},
					"mac": "00:16:3e:13:2d:1b",
					"com.volcengine.k8s.network-interface": &types.NetworkInterfaceConfig{
						Type: "trunk",
						IPs: []*ip.IP{
							ip.ParseIP("192.168.10.128/24"),
							ip.ParseIP("2406:d440:10a:ff00:947f:e925:dc9a:bbb8/64"),
						},
						Mac: "00:16:3e:13:2d:1b",
						Trunk: &types.NetworkInterfaceTrunkConfig{
							VlanID:   "1",
							TrunkMac: "00:16:3e:72:be:e4",
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createCNIRuntimeConf(tt.args.args, tt.args.k8sArgs, tt.args.netConf, tt.args.d, tt.args.ifName)
			if !tt.wantErr(t, err, fmt.Sprintf("createCNIRuntimeConf(%v, %v, %v, %v, %v)", tt.args.args, tt.args.k8sArgs, tt.args.netConf, tt.args.d, tt.args.ifName)) {
				return
			}
			assert.Equalf(t, tt.want, got, "createCNIRuntimeConf(%v, %v, %v, %v, %v)", tt.args.args, tt.args.k8sArgs, tt.args.netConf, tt.args.d, tt.args.ifName)
		})
	}
}
