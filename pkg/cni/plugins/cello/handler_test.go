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

package cello

import (
	"fmt"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/stretchr/testify/assert"

	"github.com/volcengine/cello/pkg/cni/types"
	"github.com/volcengine/cello/pkg/pbrpc"
)

func TestParseConfigs(t *testing.T) {
	cniVersion := "0.3.1"
	redirectCIDRs := []string{"169.254.0.0/16", "2408:1000:abff:ff::/56"}
	localFastPath := "true"
	containerId := "icee6giejonei6sohng6ahngee7laquohquee9shiGo7fohferakah3Feiyoolu2pei7ciPhoh7shaoX6vai3vuf0ahfaeng8yohb9ceu0daez5hashee8ooYai5wa3y"
	podName := "test-123456"
	podNameSpace := "default"
	sb := strings.Builder{}
	for i, redirectCIDR := range redirectCIDRs {
		sb.WriteString("\"" + redirectCIDR + "\"")
		if i < len(redirectCIDRs)-1 {
			sb.WriteRune(',')
		}

	}
	configBytes := []byte(fmt.Sprintf(`
	{
		"name": "cello-test",
		"type": "cello",
		"cniVersion": "%s",
		"redirectToHostCIDRs": [%v],
		"localFastPath": %s
	}`, cniVersion, sb.String(), localFastPath))
	k8sConf := fmt.Sprintf("K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=%s",
		podName, podNameSpace, containerId)

	args := &skel.CmdArgs{
		ContainerID: containerId,
		Netns:       "default",
		IfName:      "eth0",
		Args:        k8sConf,
		Path:        "/net/ns/ns1",
		StdinData:   configBytes,
	}

	gotCNIVersion, gotCNIConf, gotK8SConf, err := parseCmdArgs(args)

	// Check network config.
	assert.NoError(t, err)
	assert.Equal(t, cniVersion, gotCNIVersion)
	assert.Equal(t, localFastPath == "true", gotCNIConf.LocalFastPath)
	assert.Equal(t, redirectCIDRs, gotCNIConf.RedirectToHostCIDRs)
	assert.Equal(t, podName, string(gotK8SConf.K8S_POD_NAME))

	// Test Parse setup config.
	eniName := "eth1"
	ipv4 := "172.16.0.2"
	v4Mask := "/16"
	ipv6 := "2408:1000:abff:ff00:a6d1:b7a2:d9e3:c2f"
	v6Mask := "/56"
	networkInterface := &pbrpc.NetworkInterface{
		ENI: &pbrpc.ENI{
			ID:          "",
			Mac:         "",
			IPv4Gateway: "",
			IPv6Gateway: "",
			GatewayMac:  "",
			Subnet: &pbrpc.IPSet{
				IPv4: "172.16.0.1/16",
				IPv6: "2408:1000:abff:ff00:a6d1:b7a2:d9e3:c2f/56",
			},
			Trunk:    false,
			Vid:      0,
			SlaveMac: "",
		},
		IPv4Addr:     ipv4 + v4Mask,
		IPv6Addr:     ipv6 + v6Mask,
		IfName:       eniName,
		ExtraRoutes:  nil,
		DefaultRoute: false,
	}

	for _, ifType := range []types.IPType{types.ENISingleIP, types.ENIMultiIP} {
		gotSetupConf, err := generateSetupConfig(args, gotCNIConf, networkInterface, ifType)
		assert.NoError(t, err)
		assert.Equal(t, ipv4, gotSetupConf.IPv4.IP.String())
		assert.Equal(t, ipv6, gotSetupConf.IPv6.IP.String())
	}

	//TODO: Test parse trunk config

}
