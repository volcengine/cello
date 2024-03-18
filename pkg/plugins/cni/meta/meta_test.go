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
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
)

func Test_getIPRanges(t *testing.T) {
	type args struct {
		ipv4               *ip.IP
		ipv6               *ip.IP
		ipRangesSourceType string
	}
	tests := []struct {
		name    string
		args    args
		want    []RangeSet
		wantErr bool
	}{
		{
			name: "device ipv4 subnet",
			args: args{
				ipv4:               mustIPNet("192.168.0.2/27"),
				ipRangesSourceType: IpRangeSourceNetDeviceSubnet,
			},
			want: []RangeSet{
				{
					Range{
						RangeStart: net.ParseIP("192.168.0.3"),
						Subnet:     types.IPNet(mustIPNet("192.168.0.0/27").IPNet),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "device ipv4 subnet too small",
			args: args{
				ipv4:               mustIPNet("192.168.0.2/30"),
				ipRangesSourceType: IpRangeSourceNetDeviceSubnet,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "device ipv6 subnet",
			args: args{
				ipv6:               mustIPNet("fe::3/64"),
				ipRangesSourceType: IpRangeSourceNetDeviceSubnet,
			},
			want: []RangeSet{
				{
					Range{
						RangeStart: net.ParseIP("fe::4"),
						Subnet:     types.IPNet(mustIPNet("fe::/64").IPNet),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "device ipv6 subnet too small",
			args: args{
				ipv6:               mustIPNet("fe::3/126"),
				ipRangesSourceType: IpRangeSourceNetDeviceSubnet,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "device ipv4 and ipv6 subnet",
			args: args{
				ipv4:               mustIPNet("192.168.0.3/27"),
				ipv6:               mustIPNet("fe::3/64"),
				ipRangesSourceType: IpRangeSourceNetDeviceSubnet,
			},
			want: []RangeSet{
				{
					Range{
						RangeStart: net.ParseIP("192.168.0.4"),
						Subnet:     types.IPNet(mustIPNet("192.168.0.0/27").IPNet),
					},
				},
				{
					Range{
						RangeStart: net.ParseIP("fe::4"),
						Subnet:     types.IPNet(mustIPNet("fe::/64").IPNet),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "device ipv4 and ipv6 self",
			args: args{
				ipv4:               mustIPNet("192.168.1.3/27"),
				ipv6:               mustIPNet("fe::3/64"),
				ipRangesSourceType: IPRangeSourceNetDeviceSelf,
			},
			want: []RangeSet{
				{
					Range{
						RangeStart: net.ParseIP("192.168.1.3"),
						RangeEnd:   net.ParseIP("192.168.1.3"),
						Subnet:     types.IPNet(mustIPNet("192.168.1.0/27").IPNet),
					},
				},
				{
					Range{
						RangeStart: net.ParseIP("fe::3"),
						RangeEnd:   net.ParseIP("fe::3"),
						Subnet:     types.IPNet(mustIPNet("fe::/64").IPNet),
					},
				},
			},
		},
		{
			name: "device no ip",
			args: args{
				ipRangesSourceType: IpRangeSourceNetDeviceSubnet,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "device ip range source none",
			args: args{
				ipRangesSourceType: IPRangeSourceNone,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "device ip range source unknown",
			args: args{
				ipRangesSourceType: "unknown",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getIPRanges(tt.args.ipv4, tt.args.ipv6, tt.args.ipRangesSourceType)
			if (err != nil) != tt.wantErr {
				t.Errorf("getIPRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotJson, _ := json.Marshal(got)
			wantJson, _ := json.Marshal(tt.want)
			if !reflect.DeepEqual(gotJson, wantJson) {
				t.Errorf("getIPRanges() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_NetDeviceConfigCache(t *testing.T) {
	type args struct {
		dirPath   string
		deviceID  string
		netDevice NetDevice
	}
	tests := []struct {
		name    string
		args    args
		want    *NetDevice
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "store and load ipv4",
			args: args{
				dirPath:  "/tmp",
				deviceID: "test-123",
				netDevice: NetDevice{
					DeviceID: "test-123",
					Index:    1,
					Name:     "eth1",
					IPv4:     mustIPNet("192.168.1.3/27"),
					IPv6:     nil,
					Mac:      "ef:ef:ef:ef:ef:ef",
				},
			},
			want: &NetDevice{
				DeviceID: "test-123",
				Index:    1,
				Name:     "eth1",
				IPv4:     mustIPNet("192.168.1.3/27"),
				IPv6:     nil,
				Mac:      "ef:ef:ef:ef:ef:ef",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return false
			},
		},
		{
			name: "store and load ipv4 and ipv6",
			args: args{
				dirPath:  "/tmp",
				deviceID: "test-123",
				netDevice: NetDevice{
					DeviceID: "test-123",
					Index:    1,
					Name:     "eth1",
					IPv4:     mustIPNet("192.168.1.3/27"),
					IPv6:     mustIPNet("fe::2/64"),
					Mac:      "ef:ef:ef:ef:ef:ef",
				},
			},
			want: &NetDevice{
				DeviceID: "test-123",
				Index:    1,
				Name:     "eth1",
				IPv4:     mustIPNet("192.168.1.3/27"),
				IPv6:     mustIPNet("fe::2/64"),
				Mac:      "ef:ef:ef:ef:ef:ef",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadNetDeviceConfigCache(tt.args.dirPath, tt.args.deviceID)
			if !tt.wantErr(t, err, fmt.Sprintf("loadNetDeviceConfigCache(%v, %v)", tt.args.dirPath, tt.args.deviceID)) {
				return
			}
			assert.Equalf(t, tt.want, got, "loadNetDeviceConfigCache(%v, %v)", tt.args.dirPath, tt.args.deviceID)
		})
	}
}

func mustIPNet(ipnet string) *ip.IP {
	ret := ip.ParseIP(ipnet)
	if ret == nil {
		panic(ipnet)
	}

	return ret
}
