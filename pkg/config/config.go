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
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gdexlab/go-render/render"

	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/iproute"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/types"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "config"})

var (
	Config = &DaemonConfig{}
)

// DaemonConfig configuration of cello daemon.
type DaemonConfig struct {
	// CredentialAccessKeyId used in static authentication
	CredentialAccessKeyId *string `yaml:"credentialAccessKeyId" json:"credentialAccessKeyId,omitempty"`

	// CredentialAccessKeySecret used in static authentication
	CredentialAccessKeySecret *string `yaml:"credentialAccessKeySecret" json:"credentialAccessKeySecret,omitempty"`

	// RamRole used in dynamic authentication, mutually exclusive with static authentication and takes precedence over static authentication
	RamRole *string `yaml:"ramRole" json:"ramRole,omitempty"`

	// CredentialFile credential file for accessing volcengine api
	CredentialFile *string `yaml:"credentialFile" json:"credentialFile,omitempty"`

	// OpenApiAddress address of top gateway for accessing volc openapi
	OpenApiAddress *string `yaml:"openApiAddress" json:"openApiAddress,omitempty"`

	// EndpointConfigPath is path of service top endpoints config
	EndpointConfigPath *string `yaml:"endpointConfigPath" json:"endpointConfigPath,omitempty"`

	// SecurityGroups used by pods (actually used by ENI)
	SecurityGroups []string `yaml:"securityGroups" json:"securityGroups,omitempty"`

	// LegacySecurityGroups used for compatibility
	LegacySecurityGroups []string `yaml:"security_groups" json:"security_groups,omitempty"`

	// Subnets used by pods (actually used by ENI)
	Subnets []string `yaml:"subnets" json:"subnets,omitempty"`

	// DisabledSubnets used to disable some subnets
	DisabledSubnets []string `yaml:"disabledSubnets" json:"disabledSubnets,omitempty"`

	// HeathAndDebugPort port for heath check and debug
	HeathAndDebugPort *uint32 `yaml:"heathAndDebugPort" json:"heathAndDebugPort,omitempty"`

	// ReconcileIntervalSec ReconcileInterval of daemon expressed in seconds
	ReconcileIntervalSec *uint32 `yaml:"reconcileIntervalSec" json:"reconcileIntervalSec"`

	// pool configs of eni or eni-multi-ip mode
	// PoolTargetLimit the maximum ratio of the number of cached resources to the total quota
	PoolTargetLimit *float64 `yaml:"poolTargetLimit" json:"poolTargetLimit,omitempty"`

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

	// InterfaceTagPrefixes is the default interface tag's prefix, the first item would be used as tag prefix.
	// all the interfaces managed by cello would be tagged <first-prefix>created-by:cello and <first-prefix>ecs-id: <instance-id>.
	// Other prefixes would be used as compatible prefixes.
	InterfaceTagPrefixes []string `yaml:"interfaceTagPrefixes" json:"interfaceTagPrefixes,omitempty"`

	// AdditionalTags is the additional tags that cello will add to when creating eni.
	AdditionalTags map[string]string `yaml:"additionalTags" json:"additionalTags,omitempty"`

	// Regular apiserver request QPS limit for kube client
	KubeClientQPS *float64 `yaml:"kubeClientQPS" json:"kubeClientQPS,omitempty"`

	// Burst apiserver request QPS limit for kube client
	KubeClientBurst *int `yaml:"kubeClientBurst" json:"kubeClientBurst,omitempty"`

	// Apiserver request content type
	KubeContentType *string `yaml:"kubeContentType" json:"kubeContentType,omitempty"`

	// EnableRdmaIpam enable rdma ipam
	EnableRdmaIpam *bool `yaml:"enableRdmaIpam" json:"enableRdmaIpam,omitempty"`

	RdmaIpamDataDir *string `yaml:"rdmaIpamDataDir" json:"rdmaIpamDataDir,omitempty"`

	// ProbeRdma enable probe rdma interfaces
	ProbeRdma *bool `yaml:"probeRdma" json:"probeRdma,omitempty"`

	// CustomENIQuota specify the number of secondary eni that cello managed
	CustomENIQuota *uint32 `yaml:"customENIQuota" json:"customENIQuota,omitempty"`

	// CustomBranchENIQuota specify the number of branch eni that cello report
	CustomBranchENIQuota *uint32 `yaml:"customBranchENIQuota" json:"customBranchENIQuota,omitempty"`

	// ProjectName project name for vpc resources created by cello
	ProjectName *string `yaml:"projectName" json:"projectName,omitempty"`

	FilterStorageRdma *bool `yaml:"filterStorageRdma" json:"filterStorageRdma,omitempty"`
}

// verifyConfig verify DaemonConfig.
func (c *DaemonConfig) verifyConfig() error {
	if c.CredentialFile == nil && c.RamRole == nil &&
		(c.CredentialAccessKeyId == nil || c.CredentialAccessKeySecret == nil) {
		return fmt.Errorf("authentication method for volcengine OpenAPI is not provided")
	}

	if c.CredentialFile != nil {
		if datatype.StringValue(c.CredentialFile) == "" {
			return fmt.Errorf("credentialFile empty")
		}
		log.Infof("--CredentialFile=%s", datatype.StringValue(c.CredentialFile))
	}

	if c.RamRole != nil {
		if datatype.StringValue(c.RamRole) == "" {
			return fmt.Errorf("ramRole configured empty")
		}
		log.Infof("--RamRole=%s", datatype.StringValue(c.RamRole))
	}

	if c.CredentialAccessKeyId != nil && c.CredentialAccessKeySecret != nil {
		if datatype.StringValue(c.CredentialAccessKeyId) == "" ||
			datatype.StringValue(c.CredentialAccessKeySecret) == "" {
			return fmt.Errorf("credential configured empty")
		}
		log.Infof("--Use static Credential")
	}

	if c.OpenApiAddress == nil && c.EndpointConfigPath == nil {
		return fmt.Errorf("endpoint configured empty")
	}

	if c.OpenApiAddress != nil {
		if datatype.StringValue(c.OpenApiAddress) == "" {
			return fmt.Errorf("openApiAddress configured empty")
		}
		log.Infof("--OpenApiAddress=%s", datatype.StringValue(c.OpenApiAddress))
	}

	if c.EndpointConfigPath != nil {
		if datatype.StringValue(c.EndpointConfigPath) == "" {
			return fmt.Errorf("endpointConfigPath configured empty")
		}
		log.Infof("--EndpointConfigPath=%s", datatype.StringValue(c.EndpointConfigPath))
	}

	if len(c.SecurityGroups) == 0 {
		if len(c.LegacySecurityGroups) == 0 {
			return fmt.Errorf("securityGroups not configured")
		}
		log.Infof("Use LegacySecurityGroups security_groups")
		c.SecurityGroups = c.LegacySecurityGroups
	}
	log.Infof("--SecurityGroups=%s", c.SecurityGroups)

	if len(c.Subnets) == 0 {
		return fmt.Errorf("subnets not configured")
	}
	log.Infof("--Subnets=%s", c.Subnets)

	log.Infof("--DisabledSubnets=%s", c.DisabledSubnets)

	if datatype.Uint32Value(c.ReconcileIntervalSec) == 0 {
		c.ReconcileIntervalSec = datatype.Uint32(DefaultReconcileIntervalSec)
	}
	log.Infof("--ReconcileIntervalSec=%d", datatype.Uint32Value(c.ReconcileIntervalSec))

	c.HeathAndDebugPort = datatype.Uint32(DefaultDebugPort) // cilium uses this port to check if the cello is ready
	log.Infof("--HeathAndDebugPort=%d", datatype.Uint32Value(c.HeathAndDebugPort))

	if l := datatype.Float64Value(c.PoolTargetLimit); l <= 0 || l > 1 {
		c.PoolTargetLimit = datatype.Float64(DefaultPoolTargetLimit)
	}
	log.Infof("--PoolTargetLimit=%f", datatype.Float64Value(c.PoolTargetLimit))

	if c.PoolTarget == nil {
		c.PoolTarget = datatype.Uint32(0)
	}
	log.Infof("--PoolTarget=%d", datatype.Uint32Value(c.PoolTarget))

	if c.PoolTargetMin == nil {
		c.PoolTargetMin = datatype.Uint32(0)
	}
	log.Infof("--PoolTargetMin=%d", datatype.Uint32Value(c.PoolTargetMin))

	if c.PoolMaxCap == nil {
		c.PoolMaxCapProbe = datatype.Bool(true)
		c.PoolMaxCap = datatype.Uint32(0)
	}

	log.Infof("--PoolMaxCap=%d", datatype.Uint32Value(c.PoolMaxCap))
	log.Infof("--PoolMaxCapProbe=%t", datatype.BoolValue(c.PoolMaxCapProbe))

	if datatype.Uint32Value(c.PoolMonitorIntervalSec) == 0 {
		c.PoolMonitorIntervalSec = datatype.Uint32(DefaultPoolMonitorIntervalSec)
	}
	log.Infof("--PoolMonitorIntervalSec=%d", datatype.Uint32Value(c.PoolMonitorIntervalSec))

	if datatype.Uint32Value(c.SubnetStatAgingSec) == 0 {
		c.SubnetStatAgingSec = datatype.Uint32(DefaultSubnetStatAgingSec)
	}
	log.Infof("--SubnetStatAgingSec=%d", datatype.Uint32Value(c.SubnetStatAgingSec))

	if datatype.Uint32Value(c.SubnetStatUpdateIntervalSec) == 0 {
		c.SubnetStatUpdateIntervalSec = datatype.Uint32(DefaultSubnetStatUpdateIntervalSec)
	}
	log.Infof("--SubnetStatUpdateIntervalSec=%d", datatype.Uint32Value(c.SubnetStatUpdateIntervalSec))

	if datatype.Uint32Value(c.PoolGCProtectPeriodSec) == 0 {
		c.PoolGCProtectPeriodSec = datatype.Uint32(DefaultGcProtectPeriodSec)
	}
	log.Infof("--PoolGCProtectPeriodSec=%d", datatype.Uint32Value(c.PoolGCProtectPeriodSec))

	if c.EnableTrunk == nil {
		c.EnableTrunk = datatype.Bool(false)
	}
	log.Infof("--EnableTrunk=%t", datatype.BoolValue(c.EnableTrunk))

	if c.NetworkMode == nil {
		c.NetworkMode = datatype.String(NetworkModeENIShare)
	}
	log.Infof("--NetworkMode=%s", datatype.StringValue(c.NetworkMode))

	if c.IPFamily == nil {
		c.IPFamily = datatype.String(types.IPFamilyIPv4)
	}
	if v := datatype.StringValue(c.IPFamily); v != types.IPFamilyIPv4 &&
		v != types.IPFamilyIPv6 &&
		v != types.IPFamilyDual {
		return fmt.Errorf("IPFamily %s not support", datatype.StringValue(c.IPFamily))
	}
	// check host ip family enable
	ipFamily := types.IPFamily(*c.IPFamily)
	hostIPSet, err := iproute.GetHostIP()
	if err != nil {
		log.ErrorS(err, "get host ip failed")
	}
	if ipFamily.EnableIPv4() && hostIPSet.IPv4 == nil {
		return fmt.Errorf("IPFamily is %s, ip stack of host does not support, %v", datatype.StringValue(c.IPFamily), err)
	}
	if ipFamily.EnableIPv6() && hostIPSet.IPv6 == nil {
		return fmt.Errorf("IPFamily is %s, ip stack of host does not support, %v", datatype.StringValue(c.IPFamily), err)
	}

	log.Infof("--IPFamily=%s", datatype.StringValue(c.IPFamily))

	log.Infof("--Source=%s", datatype.StringValue(c.Source))

	if len(c.InterfaceTagPrefixes) == 0 {
		c.InterfaceTagPrefixes = []string{InterfaceTagPrefixForVKE}
	}
	log.Infof("--InterfaceTagPrefix=%s", c.InterfaceTagPrefixes)

	if c.AdditionalTags == nil {
		c.AdditionalTags = make(map[string]string)
	}
	log.Infof("--AdditionalTags=%v", c.AdditionalTags)

	if c.EnableRdmaIpam == nil {
		c.EnableRdmaIpam = datatype.Bool(true)
	}
	log.Infof("--EnableRdmaIpam=%t", datatype.BoolValue(c.EnableRdmaIpam))

	if c.RdmaIpamDataDir == nil {
		c.RdmaIpamDataDir = datatype.String(DefaultRdmaIpamDataDir)
	}
	log.Infof("--RdmaIpamDataDir=%s", datatype.StringValue(c.RdmaIpamDataDir))

	if c.ProbeRdma == nil {
		c.ProbeRdma = datatype.Bool(true)
	}
	log.Infof("--ProbeRdma=%t", datatype.BoolValue(c.ProbeRdma))

	if c.CustomENIQuota == nil {
		c.CustomENIQuota = datatype.Uint32(0)
	}
	log.Infof("--CustomENIQuota=%d", datatype.Uint32Value(c.CustomENIQuota))

	if c.CustomBranchENIQuota == nil {
		c.CustomBranchENIQuota = datatype.Uint32(0)
	}
	log.Infof("--CustomBranchENIQuota=%d", datatype.Uint32Value(c.CustomBranchENIQuota))

	// Nil is used to indicate that ProjectName need obtained by calling the API.
	log.Infof("--ProjectName=%s", datatype.StringValue(c.ProjectName))

	if c.FilterStorageRdma == nil {
		c.FilterStorageRdma = datatype.Bool(false)
	}
	log.Infof("--FilterStorageRdma=%t", datatype.BoolValue(c.FilterStorageRdma))

	return nil
}

// ParseConfig Parse DaemonConfig from configmap.
func ParseConfig(k8s k8s.Service) error {
	cfg, err := GetMergedConfigFromConfigMap(k8s)
	if err != nil {
		return err
	}

	// parse config that not from configmap
	localNode, err := k8s.GetLocalNode(context.TODO())
	if err != nil {
		return fmt.Errorf("get local node err, %v", err)
	}

	// use node label
	if cfg.ProjectName == nil {
		if projectName, exist := localNode.Labels[types.LabelProjectNameKey]; !exist {
			// If key not exist, use "" as value
			cfg.ProjectName = datatype.String("")
		} else if projectName != "" { // If key exists but value is "", set to nil
			cfg.ProjectName = datatype.String(projectName)
		}
	}

	err = cfg.verifyConfig()
	if err != nil {
		return err
	}
	Config = cfg
	return nil
}

func (c *DaemonConfig) verifyStaticConfig() error {
	if datatype.Float64Value(c.KubeClientQPS) == 0 {
		c.KubeClientQPS = datatype.Float64(DefaultKubeClientQPS)
	}
	log.Infof("--KubeClientQPS=%f", datatype.Float64Value(c.KubeClientQPS))

	if datatype.IntValue(c.KubeClientBurst) == 0 {
		c.KubeClientBurst = datatype.Int(DefaultKubeClientBurst)
	}
	log.Infof("--KubeClientBurst=%d", datatype.IntValue(c.KubeClientBurst))

	if datatype.StringValue(c.KubeContentType) == "" {
		c.KubeContentType = datatype.String(DefaultKubeContentType)
	}
	log.Infof("--KubeContentType=%s", datatype.StringValue(c.KubeContentType))
	return nil
}

// ParseStaticConfig Get configMap from mounted config file, note this func does not fill config with default data
func ParseStaticConfig(configPath string) (*DaemonConfig, error) {
	configMapFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	cfg := &DaemonConfig{}
	err = json.Unmarshal(configMapFile, &cfg)
	if err != nil {
		return nil, err
	}

	err = cfg.verifyStaticConfig()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *DaemonConfig) String() string {
	if c == nil {
		return ""
	}
	return render.AsCode(c)
}
