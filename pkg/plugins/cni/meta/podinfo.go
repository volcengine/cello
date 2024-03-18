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
	"os"
	"path"
	"time"

	"github.com/google/renameio"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/volcengine/cello/pkg/plugins/log"
	"github.com/volcengine/cello/pkg/plugins/types"
)

func buildPodInfo(podNamespace, podName, sandboxID, netNs string, confs []*DelegateNetConf, networkStatus []*NetworkStatus) (*types.PodInfo, error) {
	var resourceInfoList []*types.ContainerResource
	podInfo := &types.PodInfo{
		Version:    types.PodInfoVersion10,
		CreateTime: v1.NewTime(time.Now()),
		SandboxID:  sandboxID,
		Namespace:  podNamespace,
		Name:       podName,
		NetNs:      netNs,
	}
	var err error
	if len(confs) != len(networkStatus) {
		return nil, fmt.Errorf("missmatch number delegateNetConf(%d) and networkStatus(%d)", len(confs), len(networkStatus))
	}
	for _, conf := range confs {
		if conf.MetaConfig.DeviceID != "" {
			if resourceInfoList, err = getPodContainerResourceMap(podNamespace, podName); err != nil {
				log.Log.Errorf("Get pod %s/%s container resource map failed, %v", podNamespace, podName, err)
				return nil, err
			}
			break
		}
	}
	if len(resourceInfoList) > 0 {
		podInfo.ResourceMap = &types.ResourceMap{}
		for _, resourceInfo := range resourceInfoList {
			podInfo.ResourceMap.Containers = append(podInfo.ResourceMap.Containers, resourceInfo)
		}
	}
	for i := range confs {
		ni := &types.NetworkInterface{
			Name: networkStatus[i].DeviceInfo.IfName,
			CNI:  networkStatus[i].CNIName,
			Mac:  networkStatus[i].DeviceInfo.Mac,
			IPs:  networkStatus[i].DeviceInfo.IPs,
		}
		if confs[i].MetaConfig.DeviceID != "" {
			ni.Device = &types.NetworkInterfaceDevice{
				ResourceName: confs[i].MetaRequest.ResourceName,
				DeviceID:     confs[i].MetaConfig.OriginalDeviceID,
				PciAddress:   confs[i].MetaConfig.DeviceID,
			}
		}
		podInfo.NetworkInterfaces = append(podInfo.NetworkInterfaces, ni)
	}

	return podInfo, nil
}

func updatePodInfo(podNamespace, podName, sandboxID, netNS string, delegates []*DelegateNetConf, netStatus []*NetworkStatus) error {
	podInfoFile := path.Join(defaultCNIMetaPodInfoDir, fmt.Sprintf("%s_%s", podNamespace, podName))
	if podInfo, err := buildPodInfo(podNamespace, podName, sandboxID, netNS, delegates, netStatus); err == nil {
		podInfoStr, _ := json.Marshal(podInfo)
		if err = os.MkdirAll(defaultCNIMetaPodInfoDir, 0700); err != nil {
			return fmt.Errorf("make dir %s failed, %v", defaultCNIMetaPodInfoDir, err)
		}
		if err = renameio.WriteFile(podInfoFile, podInfoStr, 0644); err != nil {
			return fmt.Errorf("write pod info to file %s failed, %v", podInfoFile, err)
		}
	} else {
		return fmt.Errorf("build pod info failed, %v", err)
	}

	return nil
}

func removePodInfo(podNamespace, podName, sandboxID string) error {
	var errs []error
	podInfoFile := podInfoPath(podNamespace, podName)
	pi, err := loadPodInfo(podInfoFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		errs = append(errs, err)
	}
	if err == nil && pi != nil {
		if pi.SandboxID != "" && sandboxID != "" && pi.SandboxID != sandboxID {
			// pod recreated, skip delete new pod
			lg.InfoS("Skip remove pod info with unexpected pod sandbox id", "namespace", podNamespace, "name", podName, "sandbox", sandboxID, "oldSandbox", pi.SandboxID)
			return nil
		}
	}

	if err = os.Remove(podInfoFile); err != nil {
		errs = append(errs, err)
	} // ignore_security_alert

	return errors.NewAggregate(errs)
}

func loadPodInfo(podInfoPath string) (*types.PodInfo, error) {
	b, err := os.ReadFile(podInfoPath)
	if err != nil {
		return nil, err
	}
	var pi = &types.PodInfo{}
	if err = json.Unmarshal(b, pi); err != nil {
		return nil, fmt.Errorf("unmarshal pod info failed")
	}

	return pi, nil
}

func podInfoPath(podNamespace, podName string) string {
	return path.Join(defaultCNIMetaPodInfoDir, fmt.Sprintf("%s_%s", podNamespace, podName))
}
