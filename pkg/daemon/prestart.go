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

package daemon

import (
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/volcengine/cello/pkg/utils/netns"
	"github.com/volcengine/cello/types"
)

// UpdateLocalPodDB migrate local Pod persistence DB to the current version.
func UpdateLocalPodDB() error {
	log.Infof("Start convert pod format in persistence db")

	ipNsMapping := map[string]string{}
	namespaces, err := netns.ListAllNetNs()
	if err != nil {
		return fmt.Errorf("list all netns failed, %v", err)
	}
	for _, namespace := range namespaces {
		ips, err := GetPodIPs(namespace)
		if err != nil {
			log.Error("get ips of pod %s failed, %v", namespace, err)
			continue
		}
		for _, ip := range ips {
			ipNsMapping[ip] = namespace
		}
	}

	podPersist, err := newPodPersistenceManager(podPersistencePath, "pod")
	if err != nil {
		return fmt.Errorf("open persistence db failed: %v", err)
	}
	pods, err := podPersist.List()
	if err != nil {
		return fmt.Errorf("list pod from persistence db failed, %v", err)
	}

	for _, pod := range pods {
		if pod.PodNetworkMode != "" && pod.NetNs != "" {
			continue
		}
		if pod.PodNetworkMode == "" {
			resIPv4, _, err := net.ParseCIDR(pod.MainInterface.IPv4Addr)
			if err != nil {
				return fmt.Errorf("parse ipv4Addr %s failed, %v", pod.MainInterface.IPv4Addr, err)
			}
			resIPSet := types.IPSet{
				IPv4: resIPv4,
				IPv6: nil,
			}
			resId := fmt.Sprintf("%s/%s", pod.MainInterface.ENI.ID, resIPSet.String())
			resType := types.NetResourceTypeEniIp
			pod.PodNetworkMode = types.PodNetworkModeENIShare
			if !pod.IsMainInterfaceSharedMode {
				resType = types.NetResourceTypeEni
				resId = pod.MainInterface.ENI.ID
				pod.PodNetworkMode = types.PodNetworkModeENIExclusive
			}
			pod.Resources = append(pod.Resources, types.VPCResource{
				Type:   resType,
				ID:     resId,
				ENIId:  pod.MainInterface.ENI.ID,
				ENIMac: pod.MainInterface.ENI.Mac,
				IPv4:   resIPv4.String(),
			})
		}
		if pod.NetNs == "" {
			podIP, _, err := net.ParseCIDR(pod.MainInterface.IPv4Addr)
			if err != nil {
				return fmt.Errorf("parse ipv4Addr %s failed, %v", pod.MainInterface.IPv4Addr, err)
			}
			if nsPath, exist := ipNsMapping[podIP.String()]; exist {
				pod.NetNs = nsPath
			}
		}

		err = podPersist.Put(pod)
		if err != nil {
			return fmt.Errorf("put pod %v to persistence db failed, %v", pod, err)
		}
	}

	podPersist.Close()
	log.Infof("Convert pod format in persistence db success")
	return nil
}

func GetPodIPs(nsPath string) ([]string, error) {
	var ips []string
	nsHandle, err := ns.GetNS(nsPath)
	if err != nil {
		log.Error("get ns handle of %s failed, %v", nsPath, err)
		return nil, err
	}
	defer func() {
		err = nsHandle.Close()
		if err != nil {
			log.Error("close netns %s failed, %v", nsPath, err)
		}
	}()

	err = nsHandle.Do(func(netNS ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("list link failed, %v", err)
		}
		for _, link := range links {
			addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
			if err != nil {
				log.Error("list addr of %s failed, %v", link.Attrs().Name, err)
				continue
			}
			for _, addr := range addrs {
				if addr.IPNet != nil {
					ips = append(ips, addr.IPNet.IP.String())
				}
			}
		}
		return nil
	})
	return ips, nil
}
