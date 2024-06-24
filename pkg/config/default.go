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

package config

import "k8s.io/apimachinery/pkg/runtime"

const (
	SourceClusterConfigMap   = "clusterConfigMap"
	SourceNodeMerged         = "nodeMerged"
	NetworkModeENIShare      = "eni_shared"
	NetworkModeENIExclusive  = "eni_exclusive"
	InterfaceTagPrefixForVKE = "volc:vke:"

	// DefaultDebugPort is the port for debug and prometheus metrics.
	DefaultDebugPort                   = 11414
	DefaultPoolTargetLimit             = 1
	DefaultPoolMonitorIntervalSec      = 120
	DefaultSubnetStatAgingSec          = 40
	DefaultSubnetStatUpdateIntervalSec = 120
	DefaultReconcileIntervalSec        = 1200
	DefaultGcProtectPeriodSec          = 120

	DefaultKubeClientQPS   = 5.0
	DefaultKubeClientBurst = 10
	DefaultKubeContentType = runtime.ContentTypeProtobuf

	DefaultRdmaIpamDataDir = "/var/run/cello/rdma-ipam"
)
