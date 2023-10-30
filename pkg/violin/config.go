// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package violin

import (
	"net"

	"k8s.io/apimachinery/pkg/runtime"
)

const (
	DefaultRPCAddress      = "/var/run/cello/cni.socket"
	DefaultConfigDir       = "/etc/cello"
	DefaultKubeClientQPS   = float64(5.0)
	DefaultKubeClientBurst = 10
	DefaultKubeContentType = runtime.ContentTypeJSON
	DefaultUserAgent       = "cello-lite/" + Version
	DefaultIpamStoreDir    = "/var/run/cello/ipam"
	IPAMStatic             = "static"
	IPAMRange              = "range"
)

type Config struct {
	NodeName *string `yaml:"nodeName" json:"nodeName,omitempty"`
	// KubeAPI includes parameters of liteAgent's request for kube API server.
	KubeClientQPS   *float64 `yaml:"kubeClientQPS,omitempty" json:"QPS,omitempty"`
	KubeClientBurst *int     `yaml:"kubeClientBurst,omitempty" json:"burst,omitempty"`
	UserAgent       *string  `yaml:"userAgent" json:"userAgent,omitempty"`
	APIAddress      *string  `yaml:"apiAddress" json:"apiAddress,omitempty"`
	EnableIPAM      bool     `yaml:"enableIPAM" json:"enableIPAM"`
	// Networks is a list of network interfaces that liteAgent is supposed to manage.
	Networks *NetworkConfig `yaml:"networks" json:"networks,omitempty"`
}

type NetworkConfig struct {
	IpamStoreDir *string        `yaml:"ipamStoreDir" json:"ipamStoreDir,omitempty"`
	DevicePrefix *string        `yaml:"devicePrefix" json:"devicePrefix,omitempty"`
	Devices      []NetDevConfig `yaml:"devices" json:"devices,omitempty"`
}

type NetDevConfig struct {
	// DeviceName is the name of device to be managed.
	DeviceName string `yaml:"device" json:"Device,omitempty"`
	// IpamMode is the IPAM mode for device to use
	// - "static": config static ip address for interface
	// - "range": device-local IPAM.
	// - "detect": auto-detect cidr from device.
	IpamMode  string `json:"IPAM,omitempty" `
	Addresses []struct {
		Address net.IPNet `json:"address"`
		Gateway net.IP    `json:"gateway,omitempty"`
	} `json:"Addresses,omitempty"`
	Ranges []struct {
		Subnet  net.IPNet `json:"subnet"`
		Gateway net.IP    `json:"gateway,omitempty"`
		Start   net.IP    `json:"start,omitempty"`
		End     net.IP    `json:"end,omitempty"`
	} `json:"Ranges,omitempty"`
	Routes []struct {
		Dst net.IPNet `json:"dst"`
	} `json:"routes,omitempty"`
}
