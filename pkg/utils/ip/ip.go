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

package ip

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/util/sets"
)

// ParseIP parse string to net.IP.
func ParseIP(ip string) (net.IP, error) {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return nil, fmt.Errorf("invalid ip [%s]", ip)
	}
	return netIP, nil
}

// ParseIPs parse string slice to net.IP slice.
func ParseIPs(ips []string) ([]net.IP, error) {
	var result []net.IP
	for _, ipStr := range ips {
		ip, err := ParseIP(ipStr)
		if err != nil {
			return nil, err
		}
		result = append(result, ip)
	}
	return result, nil
}

// ToStringSlice convert net.IP slice of ips to string slice.
func ToStringSlice(ips []net.IP) []string {
	var result []string
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result
}

// NetIPContainAll return true if all items in b can be found in a.
func NetIPContainAll(a, b []net.IP) bool {
	return sets.NewString(ToStringSlice(a)...).HasAll(ToStringSlice(b)...)
}

// NetIPContainAny return true if any items in b can be found in a.
func NetIPContainAny(a, b []net.IP) bool {
	return sets.NewString(ToStringSlice(a)...).HasAny(ToStringSlice(b)...)
}

// NetIPToMap convert slice of net.IP to map that key is string.
func NetIPToMap(ips []net.IP) map[string]net.IP {
	result := make(map[string]net.IP)
	for _, ip := range ips {
		result[ip.String()] = ip
	}
	return result
}
