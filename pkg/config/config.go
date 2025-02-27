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

import (
	"fmt"

	"github.com/gdexlab/go-render/render"

	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/types"
)

const (
	SourceClusterConfigMap  = "clusterConfigMap"
	SourceNodeMerged        = "nodeMerged"
	NetworkModeENIShare     = "eni_shared"
	NetworkModeENIExclusive = "eni_exclusive"
	PlatformVKE             = "vke"

	// DefaultDebugPort is the port for debug and prometheus metrics.
	DefaultDebugPort                   = 11414
	DefaultPoolTargetLimit             = 1
	DefaultPoolMonitorIntervalSec      = 120
	DefaultSubnetStatAgingSec          = 40
	DefaultSubnetStatUpdateIntervalSec = 60
	DefaultReconcileIntervalSec        = 1200
	DefaultGcProtectPeriodSec          = 120
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "config"})

// Config configuration of cello daemon.
type Config struct {
	// CredentialServerAddress address of credential server, if not set, take the default value of sdk
	CredentialServerAddress *string `yaml:"credentialServerAddress" json:"credentialServerAddress,omitempty"`

	// CredentialAccessKeyId used in static authentication
	CredentialAccessKeyId *string `yaml:"credentialAccessKeyId" json:"credentialAccessKeyId,omitempty"`

	// CredentialAccessKeySecret used in static authentication
	CredentialAccessKeySecret *string `yaml:"credentialAccessKeySecret" json:"credentialAccessKeySecret,omitempty"`

	// RamRole used in dynamic authentication, mutually exclusive with static authentication and takes precedence over static authentication
	RamRole *string `yaml:"ramRole" json:"ramRole,omitempty"`

	// OpenApiAddress address of top gateway for accessing volc openapi
	OpenApiAddress *string `yaml:"openApiAddress" json:"openApiAddress,omitempty"`

	// EndpointConfigPath path of service top endpoints config
	EndpointConfigPath *string `yaml:"endpointConfigPath" json:"endpointConfigPath,omitempty"`

	// SecurityGroups used by pods (actually used by ENI)
	SecurityGroups []string `yaml:"securityGroups" json:"securityGroups,omitempty"`

	// LegacySecurityGroups used for compatibility
	LegacySecurityGroups []string `yaml:"security_groups" json:"security_groups,omitempty"`

	// Subnets used by pods (actually used by ENI)
	Subnets []string `yaml:"subnets" json:"subnets,omitempty"`

	// HeathAndDebugPort port for heath check and debug
	HeathAndDebugPort *uint32 `yaml:"heathAndDebugPort" json:"heathAndDebugPort,omitempty"`

	// ReconcileIntervalSec ReconcileInterval of daemon expressed in seconds
	ReconcileIntervalSec *uint32 `yaml:"reconcileIntervalSec" json:"reconcileIntervalSec"`

	// pool configs of eni or eni-multi-ip mode
	// PoolTargetLimit the maximum ratio of the number of cached resources to the total quota
	PoolTargetLimit *float64 `yaml:"PoolTargetLimit" json:"poolTargetLimit,omitempty"`

	// PoolTarget the target number of cached resources
	PoolTarget *uint32 `yaml:"poolTarget" json:"poolTarget,omitempty"`

	// PoolTargetMin the min number of cached resources and used resources
	PoolTargetMin *uint32 `yaml:"poolTargetMin" json:"poolTargetMin,omitempty"`

	// PoolMaxCap max capacity of resources Pool
	PoolMaxCap *uint32 `yaml:"poolMaxCap" json:"poolMaxCap,omitempty"`

	// PoolMaxCapProbe enable PoolMaxCap automatic detection
	PoolMaxCapProbe *bool `yaml:"poolMaxCapProbe" json:"poolMaxCapProbe,omitempty"`

	// PoolMonitorIntervalSec  PoolMonitorInterval expressed in seconds
	PoolMonitorIntervalSec *uint32 `yaml:"poolMonitorIntervalSec" json:"poolMonitorIntervalSec,omitempty"`

	// PoolGCProtectPeriodSec protect period in seconds of resource while gc action
	PoolGCProtectPeriodSec *uint32 `yaml:"poolGCProtectPeriodSec" json:"poolGCProtectPeriodSec,omitempty"`

	// SubnetStatAgingSec SubnetStatAging expressed in seconds
	SubnetStatAgingSec *uint32 `yaml:"subnetStatAgingSec" json:"subnetStatAgingSec,omitempty"`

	// SubnetStatUpdateIntervalSec SubnetStatUpdateInterval expressed in seconds
	SubnetStatUpdateIntervalSec *uint32 `yaml:"subnetStatUpdateIntervalSec" json:"subnetStatUpdateIntervalSec,omitempty"`

	// EnableTrunk enable trunk
	EnableTrunk *bool `yaml:"enableTrunk" json:"enableTrunk,omitempty"`

	// NetworkMode network mode of cello
	NetworkMode *string `yaml:"networkMode" json:"networkMode,omitempty"`

	// IPFamily protocol stack
	IPFamily *string `yaml:"ipFamily" json:"ipFamily,omitempty"`

	// Source config source
	Source *string `yaml:"source" json:"source,omitempty"`

	// Platform is the platform used by user to deploy the kubernetes cluster. Optional values:
	// - "vke": The cluster is provided by Volcengine Kubernetes Engine(VKE).
	// - "kubernetes": The cluster is hosted by user(self-managed).
	Platform *string `yaml:"platform" json:"platform,omitempty"`
}

// verifyConfig verify Config.
func verifyConfig(cfg *Config) error {
	if cfg.RamRole == nil && (cfg.CredentialAccessKeyId == nil || cfg.CredentialAccessKeySecret == nil) {
		return fmt.Errorf("authentication method for accessing volc api is not provided")
	}

	if cfg.RamRole != nil {
		cfg.CredentialAccessKeyId = nil
		cfg.CredentialAccessKeySecret = nil
		cfg.CredentialServerAddress = nil
		if datatype.StringValue(cfg.RamRole) == "" {
			return fmt.Errorf("ramRole configured empty")
		}
		log.Infof("--RamRole=%s", datatype.StringValue(cfg.RamRole))
	}

	if cfg.CredentialAccessKeyId != nil && cfg.CredentialAccessKeySecret != nil {
		cfg.RamRole = nil
		if datatype.StringValue(cfg.CredentialAccessKeyId) == "" ||
			datatype.StringValue(cfg.CredentialAccessKeySecret) == "" {
			return fmt.Errorf("credential configured empty")
		}
		log.Infof("--Use static Credential")
	}

	if cfg.OpenApiAddress != nil {
		if datatype.StringValue(cfg.OpenApiAddress) == "" {
			return fmt.Errorf("openApiAddress configured empty")
		}
		log.Infof("--OpenApiAddress=%s", datatype.StringValue(cfg.OpenApiAddress))
	}

	if len(cfg.SecurityGroups) == 0 {
		if len(cfg.LegacySecurityGroups) == 0 {
			return fmt.Errorf("securityGroups not configured")
		}
		log.Infof("Use LegacySecurityGroups security_groups")
		cfg.SecurityGroups = cfg.LegacySecurityGroups
	}
	log.Infof("--SecurityGroups=%s", cfg.SecurityGroups)

	if len(cfg.Subnets) == 0 {
		return fmt.Errorf("subnets not configured")
	}
	log.Infof("--Subnets=%s", cfg.Subnets)

	if datatype.Uint32Value(cfg.ReconcileIntervalSec) == 0 {
		cfg.ReconcileIntervalSec = datatype.Uint32(DefaultReconcileIntervalSec)
	}
	log.Infof("--ReconcileIntervalSec=%d", datatype.Uint32Value(cfg.ReconcileIntervalSec))

	cfg.HeathAndDebugPort = datatype.Uint32(DefaultDebugPort) // cilium uses this port to check if the cello is ready
	log.Infof("--HeathAndDebugPort=%d", datatype.Uint32Value(cfg.HeathAndDebugPort))

	if l := datatype.Float64Value(cfg.PoolTargetLimit); l <= 0 || l > 1 {
		cfg.PoolTargetLimit = datatype.Float64(DefaultPoolTargetLimit)
	}
	log.Infof("--PoolTargetLimit=%f", datatype.Float64Value(cfg.PoolTargetLimit))

	if cfg.PoolTarget == nil {
		cfg.PoolTarget = datatype.Uint32(0)
	}
	log.Infof("--PoolTarget=%d", datatype.Uint32Value(cfg.PoolTarget))

	if cfg.PoolTargetMin == nil {
		cfg.PoolTargetMin = datatype.Uint32(0)
	}
	log.Infof("--PoolTargetMin=%d", datatype.Uint32Value(cfg.PoolTargetMin))

	if cfg.PoolMaxCap == nil {
		cfg.PoolMaxCapProbe = datatype.Bool(true)
		cfg.PoolMaxCap = datatype.Uint32(0)
	}

	log.Infof("--PoolMaxCap=%d", datatype.Uint32Value(cfg.PoolMaxCap))
	log.Infof("--PoolMaxCapProbe=%t", datatype.BoolValue(cfg.PoolMaxCapProbe))

	if datatype.Uint32Value(cfg.PoolMonitorIntervalSec) == 0 {
		cfg.PoolMonitorIntervalSec = datatype.Uint32(DefaultPoolMonitorIntervalSec)
	}
	log.Infof("--PoolMonitorIntervalSec=%d", datatype.Uint32Value(cfg.PoolMonitorIntervalSec))

	if datatype.Uint32Value(cfg.SubnetStatAgingSec) == 0 {
		cfg.SubnetStatAgingSec = datatype.Uint32(DefaultSubnetStatAgingSec)
	}
	log.Infof("--SubnetStatAgingSec=%d", datatype.Uint32Value(cfg.SubnetStatAgingSec))

	if datatype.Uint32Value(cfg.SubnetStatUpdateIntervalSec) == 0 {
		cfg.SubnetStatUpdateIntervalSec = datatype.Uint32(DefaultSubnetStatUpdateIntervalSec)
	}
	log.Infof("--SubnetStatUpdateIntervalSec=%d", datatype.Uint32Value(cfg.SubnetStatUpdateIntervalSec))

	if datatype.Uint32Value(cfg.PoolGCProtectPeriodSec) == 0 {
		cfg.PoolGCProtectPeriodSec = datatype.Uint32(DefaultGcProtectPeriodSec)
	}
	log.Infof("--PoolGCProtectPeriodSec=%d", datatype.Uint32Value(cfg.PoolGCProtectPeriodSec))

	if cfg.EnableTrunk == nil {
		cfg.EnableTrunk = datatype.Bool(false)
	}
	log.Infof("--EnableTrunk=%t", datatype.BoolValue(cfg.EnableTrunk))

	if cfg.NetworkMode == nil {
		cfg.NetworkMode = datatype.String(NetworkModeENIShare)
	}
	log.Infof("--NetworkMode=%s", datatype.StringValue(cfg.NetworkMode))

	if cfg.IPFamily == nil {
		cfg.IPFamily = datatype.String(types.IPFamilyIPv4)
	}
	if v := datatype.StringValue(cfg.IPFamily); v != types.IPFamilyIPv4 &&
		v != types.IPFamilyIPv6 &&
		v != types.IPFamilyDual {
		return fmt.Errorf("IPFamily %s not support", datatype.StringValue(cfg.IPFamily))
	}
	// check host ip family enable
	ipFamily := types.IPFamily(*cfg.IPFamily)
	hostIPSet, err := iproute.GetHostIP()
	if err != nil {
		log.Warnf("get host ip failed: %v", err)
	}
	if ipFamily.EnableIPv4() && hostIPSet.IPv4 == nil {
		return fmt.Errorf("IPFamily is %s, ip stack of host does not support, %v", datatype.StringValue(cfg.IPFamily), err)
	}
	if ipFamily.EnableIPv6() && hostIPSet.IPv6 == nil {
		return fmt.Errorf("IPFamily is %s, ip stack of host does not support, %v", datatype.StringValue(cfg.IPFamily), err)
	}

	log.Infof("--IPFamily=%s", datatype.StringValue(cfg.IPFamily))

	log.Infof("--Source=%s", datatype.StringValue(cfg.Source))

	if cfg.Platform == nil {
		cfg.Platform = datatype.String(PlatformVKE)
	}
	log.Infof("--Platform=%s", datatype.StringValue(cfg.Platform))
	return nil
}

// ParseConfig Parse Config from configmap.
func ParseConfig(k8s k8s.Service) (*Config, error) {
	cfg, err := GetMergedConfigFromConfigMap(k8s)
	if err != nil {
		return nil, err
	}
	err = verifyConfig(cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) String() string {
	if c == nil {
		return ""
	}
	return render.AsCode(c)
}
