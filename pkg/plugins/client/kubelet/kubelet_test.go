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

package kubelet

import (
	"reflect"
	"testing"

	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"

	"github.com/volcengine/cello/pkg/plugins/types"
)

func Test_kubeletClient_GetPodResourceMap(t *testing.T) {
	type fields struct {
		resources []*podresourcesapi.PodResources
	}
	type args struct {
		ns   string
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]*types.ResourceInfo
		wantErr bool
	}{
		{
			name:   "kubelet return empty",
			fields: fields{},
			args: args{
				ns:   "default",
				name: "test-pod",
			},
			want:    map[string]*types.ResourceInfo{},
			wantErr: false,
		},
		{
			name: "kubelet return pod without resource",
			fields: fields{
				resources: []*podresourcesapi.PodResources{
					{
						Name:       "test-pod",
						Namespace:  "default",
						Containers: nil,
					},
				},
			},
			args: args{
				ns:   "default",
				name: "test-pod",
			},
			want:    map[string]*types.ResourceInfo{},
			wantErr: false,
		},
		{
			name: "kubelet return pod with resource",
			fields: fields{
				resources: []*podresourcesapi.PodResources{
					{
						Name:       "unknown",
						Namespace:  "default",
						Containers: nil,
					},
					{
						Name:      "test-pod",
						Namespace: "default",
						Containers: []*podresourcesapi.ContainerResources{
							{
								Name: "cont1",
								Devices: []*podresourcesapi.ContainerDevices{
									{
										ResourceName: "vke.volcengine.com/rdma",
										DeviceIds:    []string{"id1", "id2"},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				ns:   "default",
				name: "test-pod",
			},
			want: map[string]*types.ResourceInfo{
				"vke.volcengine.com/rdma": {
					Index:     0,
					DeviceIDs: []string{"id1", "id2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &kubeletClient{
				resources: tt.fields.resources,
			}
			got, err := rc.GetPodResourceMap(tt.args.ns, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPodResourceMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPodResourceMap() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_kubeletClient_GetPodContainerResourceMap(t *testing.T) {
	type fields struct {
		resources []*podresourcesapi.PodResources
	}
	type args struct {
		ns   string
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*types.ContainerResource
		wantErr bool
	}{
		{
			name:   "kubelet return empty",
			fields: fields{},
			args: args{
				ns:   "default",
				name: "test-pod",
			},
			want:    []*types.ContainerResource{},
			wantErr: false,
		},
		{
			name: "kubelet return pod without resource",
			fields: fields{
				resources: []*podresourcesapi.PodResources{
					{
						Name:       "test-pod",
						Namespace:  "default",
						Containers: nil,
					},
				},
			},
			args: args{
				ns:   "default",
				name: "test-pod",
			},
			want:    []*types.ContainerResource{},
			wantErr: false,
		},
		{
			name: "kubelet return pod with resource",
			fields: fields{
				resources: []*podresourcesapi.PodResources{
					{
						Name:       "unknown",
						Namespace:  "default",
						Containers: nil,
					},
					{
						Name:      "test-pod",
						Namespace: "default",
						Containers: []*podresourcesapi.ContainerResources{
							{
								Name: "cont1",
								Devices: []*podresourcesapi.ContainerDevices{
									{
										ResourceName: "vke.volcengine.com/rdma",
										DeviceIds:    []string{"id1", "id2"},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				ns:   "default",
				name: "test-pod",
			},
			want: []*types.ContainerResource{
				{
					Name: "cont1",
					Devices: []*types.ContainerDevices{
						{
							ResourceName: "vke.volcengine.com/rdma",
							DeviceIds:    []string{"id1", "id2"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &kubeletClient{
				resources: tt.fields.resources,
			}
			got, err := rc.GetPodContainerResourceMap(tt.args.ns, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPodContainerResourceMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPodContainerResourceMap() got = %v, want %v", got, tt.want)
			}
		})
	}
}
