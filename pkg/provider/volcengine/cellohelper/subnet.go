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

package cellohelper

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"

	"github.com/volcengine/cello/pkg/backoff"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/types"
)

const (
	defaultSubnetInsufficientThreshold = 0.2
	percentage                         = 100
)

type PodSubnet struct {
	ZoneId         string `json:"zoneId"`
	VpcId          string `json:"vpcId"`
	SubnetId       string `json:"subnetId"`
	IPv4Cidr       string `json:"ipv4Cidr,omitempty"`
	IPv6Cidr       string `json:"ipv6Cidr,omitempty"`
	TotalIpv4Count int    `json:"totalIpv4Count"`

	// status
	sync.RWMutex
	Disable                 bool      `json:"disable,omitempty"`
	AvailableIpAddressCount int       `json:"availableIpAddressCount"`
	LastUpdate              time.Time `json:"lastUpdate"`
}

func (s *PodSubnet) Enable() bool {
	s.RLock()
	defer s.RUnlock()
	return !s.Disable
}

// IPFamily return types.IPFamily of PodSubnet.
func (s *PodSubnet) IPFamily() types.IPFamily {
	s.RLock()
	defer s.RUnlock()

	if s.IPv4Cidr != "" && s.IPv6Cidr != "" {
		return types.IPFamilyDual
	} else if s.IPv6Cidr != "" {
		return types.IPFamilyIPv6
	} else {
		return types.IPFamilyIPv4
	}
}

func (s *PodSubnet) DisableSubnet() {
	s.Lock()
	defer s.Unlock()
	s.Disable = true
}

func (s *PodSubnet) EnableSubnet() {
	s.Lock()
	defer s.Unlock()
	s.Disable = false
}

func (s *PodSubnet) GetAvailableIpAddressCount() int {
	s.RLock()
	defer s.RUnlock()
	return s.AvailableIpAddressCount
}

func (s *PodSubnet) UpdateAvailableIpAddressCount(q int) {
	s.Lock()
	defer s.Unlock()
	s.AvailableIpAddressCount = q
}

func (s *PodSubnet) Available(ipFamily types.IPFamily) bool {
	s.RLock()
	defer s.RUnlock()
	if !s.Disable && s.IPFamily().Support(ipFamily) {
		if ipFamily.EnableIPv4() {
			return s.AvailableIpAddressCount > 0
		}
		return true
	}
	return false
}

type SortablePodSubnets []*PodSubnet

func (s SortablePodSubnets) Len() int {
	return len(s)
}

func (s SortablePodSubnets) Less(i, j int) bool {
	return s[i].GetAvailableIpAddressCount() < s[j].GetAvailableIpAddressCount()
}

func (s SortablePodSubnets) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type PodSubnetManagerConfig struct {
	eventRecord                 *tracing.Tracer
	EventLimiter                *rate.Limiter
	SubnetInsufficientThreshold float64
}

func DefaultPodSubnetManagerConfig() *PodSubnetManagerConfig {
	return &PodSubnetManagerConfig{
		SubnetInsufficientThreshold: defaultSubnetInsufficientThreshold,
	}
}

type PodSubnetManagerOption func(config *PodSubnetManagerConfig)

func WithEventRecord(eventRecord *tracing.Tracer) PodSubnetManagerOption {
	return func(config *PodSubnetManagerConfig) {
		config.eventRecord = eventRecord
	}
}

func WithDefaultEventLimiter() PodSubnetManagerOption {
	return func(config *PodSubnetManagerConfig) {
		config.EventLimiter = rate.NewLimiter(2, 5)
	}
}

func WithEventLimiter(limiter *rate.Limiter) PodSubnetManagerOption {
	return func(config *PodSubnetManagerConfig) {
		config.EventLimiter = limiter
	}
}

func WithSubnetInsufficientThreshold(threshold float64) PodSubnetManagerOption {
	return func(config *PodSubnetManagerConfig) {
		config.SubnetInsufficientThreshold = threshold
	}
}

type SubnetManager interface {
	// FlushSubnets flush PodSubnet in SubnetManager
	FlushSubnets(subnetIds ...string) error

	// GetPodSubnet get PodSubnet, get by openapi if not exist in SubnetManager
	GetPodSubnet(subnetId string) *PodSubnet

	// GetUpdatedPodSubnet update PodSubnet and then get it
	GetUpdatedPodSubnet(subnetId string) (subnet *PodSubnet, err error)

	// SelectSubnet select a PodSubnet from available PodSubnets in SubnetManager
	SelectSubnet(ipFamily types.IPFamily, options ...UpdateSubnetsStatusOption) *PodSubnet

	// UpdateSubnetsStatus update status of all PodSubnet in SubnetManager
	// If the option of aging is carried, subnets within the time limit will not be updated
	UpdateSubnetsStatus(options ...UpdateSubnetsStatusOption) error

	// DisableSubnet disable a PodSubnet, it will not be used
	DisableSubnet(subnetId string)

	// Status return status of SubnetManager
	Status() *Status
}

type subnetManager struct {
	vpcId  string
	zoneId string
	lock   sync.RWMutex
	// podSubnets record available subnets configured by user
	podSubnets map[string]*PodSubnet
	// legacyPodSubnet record subnets used by attached eni but not exist in podSubnets
	legacyPodSubnet map[string]*PodSubnet

	apiClient ec2.APIGroupSubnet
	config    *PodSubnetManagerConfig
}

// Status of SubnetManager.
type Status struct {
	ZoneId           string                `json:"zone_id"`
	VpcId            string                `json:"vpc_id"`
	PodSubnets       map[string]*PodSubnet `json:"pod_subnets,omitempty"`
	LegacyPodSubnets map[string]*PodSubnet `json:"legacy_pod_subnets,omitempty"`
}

func (m *subnetManager) Status() *Status {
	m.lock.RLock()
	defer m.lock.RUnlock()

	podSubnets := make(map[string]*PodSubnet)
	legacyPodSubnet := make(map[string]*PodSubnet)
	for _, subnet := range m.podSubnets {
		podSubnets[subnet.SubnetId] = subnet
	}
	for _, subnet := range m.legacyPodSubnet {
		legacyPodSubnet[subnet.SubnetId] = subnet
	}
	return &Status{
		ZoneId:           m.zoneId,
		VpcId:            m.vpcId,
		PodSubnets:       podSubnets,
		LegacyPodSubnets: legacyPodSubnet,
	}
}

// RecordSubnetEvent record events of SubnetManager.
func (m *subnetManager) RecordSubnetEvent(eventType, reason, message string) {
	if m.config.eventRecord == nil {
		return
	}

	if m.config.EventLimiter == nil || m.config.EventLimiter.Allow() {
		_ = m.config.eventRecord.RecordNodeEvent(eventType, reason, message)
	}
}

func (m *subnetManager) updateSubnets(legacy, flush bool, subnetIds ...string) error {
	var pendingMap map[string]*PodSubnet
	if legacy {
		pendingMap = m.legacyPodSubnet
	} else {
		pendingMap = m.podSubnets
	}

	var addSubnets []string
	currentPodSubnetMap := make(map[string]struct{})
	for _, sb := range subnetIds {
		currentPodSubnetMap[sb] = struct{}{}
		if _, exist := pendingMap[sb]; !exist {
			addSubnets = append(addSubnets, sb)
		}
	}

	if flush {
		// delete
		for id := range pendingMap {
			if _, exist := currentPodSubnetMap[id]; !exist {
				delete(pendingMap, id)
			}
		}
	}

	if len(addSubnets) == 0 {
		return nil
	}

	var resp *ec2.DescribeSubnetsOutput
	var err error
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		resp, err = m.apiClient.DescribeSubnets(&vpc.DescribeSubnetsInput{
			PageNumber: volcengine.Int64(1),
			PageSize:   volcengine.Int64(maxPageSize),
			SubnetIds:  volcengine.StringSlice(addSubnets),
			VpcId:      volcengine.String(m.vpcId),
		})
		return err == nil, nil
	})
	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("DescribeSubnets %s failed: %s", addSubnets, err.Error())
		return err
	}

	if len(resp.Subnets) == 0 {
		log.Errorf("Get no result while describe subnets %v in vpc %s, check if they are matched", addSubnets, m.vpcId)
	}

	for _, subnet := range resp.Subnets {
		if volcengine.StringValue(subnet.VpcId) != m.vpcId ||
			volcengine.StringValue(subnet.ZoneId) != m.zoneId {
			continue
		}
		totalCnt := int(volcengine.Int64Value(subnet.TotalIpv4Count))
		avCnt := int(volcengine.Int64Value(subnet.AvailableIpAddressCount))
		curPr := float64(avCnt) / float64(totalCnt)
		if curPr < m.config.SubnetInsufficientThreshold {
			m.RecordSubnetEvent(v1.EventTypeWarning, tracing.EventSubnetAvailableIPBelowThreshold,
				fmt.Sprintf("Current remainin of available ip in subnet %s is %.2f%%, less than %.2f%%",
					volcengine.StringValue(subnet.SubnetId), curPr*percentage, m.config.SubnetInsufficientThreshold*percentage))
		}
		pendingMap[volcengine.StringValue(subnet.SubnetId)] = &PodSubnet{
			VpcId:                   volcengine.StringValue(subnet.VpcId),
			ZoneId:                  volcengine.StringValue(subnet.ZoneId),
			SubnetId:                volcengine.StringValue(subnet.SubnetId),
			IPv4Cidr:                volcengine.StringValue(subnet.CidrBlock),
			IPv6Cidr:                volcengine.StringValue(subnet.Ipv6CidrBlock),
			TotalIpv4Count:          totalCnt,
			AvailableIpAddressCount: avCnt,
			LastUpdate:              time.Now(),
		}
	}
	return nil
}

func (m *subnetManager) DeletePodSubnet(subnetId string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.podSubnets, subnetId)
}

func (m *subnetManager) FlushSubnets(subnetIds ...string) error {
	subnetIds = removeDuplicateElement(subnetIds)
	m.lock.Lock()
	defer m.lock.Unlock()
	err := m.updateSubnets(false, true, subnetIds...)
	if err == nil {
		log.Infof("Flush subnets list: %v", subnetIds)
	}
	return err
}

func (m *subnetManager) UpdateSubnets(subnetIds ...string) error {
	subnetIds = removeDuplicateElement(subnetIds)
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.updateSubnets(false, false, subnetIds...)
}

// UpdateSubnetsStatusConfig config used while update status of PodSubnets.
type UpdateSubnetsStatusConfig struct {
	Aging time.Duration
}

// UpdateSubnetsStatusOption option used while update status of PodSubnets.
type UpdateSubnetsStatusOption func(config *UpdateSubnetsStatusConfig)

// WithAging aging option.
func WithAging(aging time.Duration) UpdateSubnetsStatusOption {
	return func(config *UpdateSubnetsStatusConfig) {
		config.Aging = aging
	}
}

// WithUnlimitedAging option for no timeliness requirement.
func WithUnlimitedAging() UpdateSubnetsStatusOption {
	return func(config *UpdateSubnetsStatusConfig) {
		config.Aging = time.Hour * 24
	}
}

func (m *subnetManager) UpdateSubnetsStatus(options ...UpdateSubnetsStatusOption) error {
	conf := &UpdateSubnetsStatusConfig{}
	for _, option := range options {
		option(conf)
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	var subnetIds []string
	for _, subnet := range m.podSubnets {
		if time.Since(subnet.LastUpdate) > conf.Aging {
			subnetIds = append(subnetIds, subnet.SubnetId)
		}
	}
	if len(subnetIds) == 0 {
		return nil
	}

	var resp *ec2.DescribeSubnetsOutput
	var err error
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		resp, err = m.apiClient.DescribeSubnets(&vpc.DescribeSubnetsInput{
			PageNumber: volcengine.Int64(1),
			PageSize:   volcengine.Int64(maxPageSize),
			SubnetIds:  volcengine.StringSlice(subnetIds),
			VpcId:      volcengine.String(m.vpcId),
		})
		return err == nil, nil
	})
	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("DescribeSubnets %s failed: %s", subnetIds, err.Error())
		return err
	}

	effectiveSubnets := make(map[string]struct{})
	for _, subnet := range resp.Subnets {
		subnetId := volcengine.StringValue(subnet.SubnetId)
		totalCnt := int(volcengine.Int64Value(subnet.TotalIpv4Count))
		avCnt := int(volcengine.Int64Value(subnet.AvailableIpAddressCount))
		curPr := float64(avCnt) / float64(totalCnt)
		if curPr < m.config.SubnetInsufficientThreshold {
			m.RecordSubnetEvent(v1.EventTypeWarning, tracing.EventSubnetAvailableIPBelowThreshold,
				fmt.Sprintf("Current remainin of available ip in subnet %s is %.2f%%, less than %.2f%%",
					subnetId, curPr*percentage, m.config.SubnetInsufficientThreshold*percentage))
		}
		effectiveSubnets[subnetId] = struct{}{}
		if sb, exist := m.podSubnets[subnetId]; exist {
			sb.UpdateAvailableIpAddressCount(avCnt)
			sb.LastUpdate = time.Now()
		}
		if sb, exist := m.legacyPodSubnet[subnetId]; exist {
			sb.UpdateAvailableIpAddressCount(avCnt)
			sb.LastUpdate = time.Now()
		}
	}

	if len(subnetIds) == len(effectiveSubnets) {
		return nil
	}

	// clean
	for _, id := range subnetIds {
		if _, exist := effectiveSubnets[id]; !exist {
			delete(m.podSubnets, id)
			delete(m.legacyPodSubnet, id)
		}
	}
	return nil
}

func (m *subnetManager) GetUpdatedPodSubnet(subnetId string) (subnet *PodSubnet, err error) {
	var resp *ec2.DescribeSubnetAttributesOutput
	werr := wait.ExponentialBackoff(backoff.BackOff(backoff.APIFastRetry), func() (bool, error) {
		resp, err = m.apiClient.DescribeSubnetAttributes(&vpc.DescribeSubnetAttributesInput{
			SubnetId: volcengine.String(subnetId),
		})
		if apiErr.ErrEqual(apiErr.InvalidSubnetNotFound, err) {
			return false, err
		}
		return err == nil, nil
	})

	if err = apiErr.BackoffErrWrapper(werr, err); err != nil {
		log.Errorf("DescribeSubnetAttributes %s failed: %s", subnetId, err.Error())
		return
	}

	totalCnt := int(volcengine.Int64Value(resp.TotalIpv4Count))
	avCnt := int(volcengine.Int64Value(resp.AvailableIpAddressCount))
	curPr := float64(avCnt) / float64(totalCnt)
	if curPr < m.config.SubnetInsufficientThreshold {
		m.RecordSubnetEvent(v1.EventTypeWarning, tracing.EventSubnetAvailableIPBelowThreshold,
			fmt.Sprintf("Current remainin of available ip in subnet %s is %.2f%%, less than %.2f%%",
				subnetId, curPr*percentage, m.config.SubnetInsufficientThreshold*percentage))
	}

	if sb, exist := m.podSubnets[subnetId]; exist {
		sb.UpdateAvailableIpAddressCount(avCnt)
		subnet = sb
		return
	}

	if sb, exist := m.legacyPodSubnet[subnetId]; exist {
		sb.UpdateAvailableIpAddressCount(avCnt)
		subnet = sb
		return
	}

	// add to legacy
	m.lock.Lock()
	defer m.lock.Unlock()

	subnet = &PodSubnet{
		ZoneId:                  volcengine.StringValue(resp.ZoneId),
		VpcId:                   volcengine.StringValue(resp.VpcId),
		SubnetId:                subnetId,
		IPv4Cidr:                volcengine.StringValue(resp.CidrBlock),
		IPv6Cidr:                volcengine.StringValue(resp.Ipv6CidrBlock),
		TotalIpv4Count:          totalCnt,
		AvailableIpAddressCount: avCnt,
		LastUpdate:              time.Now(),
	}
	m.legacyPodSubnet[subnetId] = subnet
	return
}

func (m *subnetManager) GetPodSubnet(subnetId string) *PodSubnet {
	exec := func() *PodSubnet {
		m.lock.RLock()
		defer m.lock.RUnlock()
		if subnet, exist := m.podSubnets[subnetId]; exist {
			return subnet
		}
		if subnet, exist := m.legacyPodSubnet[subnetId]; exist {
			return subnet
		}
		return nil
	}
	if subnet := exec(); subnet != nil {
		return subnet
	}

	if subnet, err := m.GetUpdatedPodSubnet(subnetId); err == nil {
		return subnet
	}
	return nil
}

func (m *subnetManager) SelectSubnet(ipFamily types.IPFamily, options ...UpdateSubnetsStatusOption) *PodSubnet {
	// update subnets status first
	err := m.UpdateSubnetsStatus(options...)
	if err != nil {
		log.Errorf("UpdateSubnetsStatus failed, %s", err.Error())
		return nil
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	subnets := SortablePodSubnets{}
	for _, subnet := range m.podSubnets {
		if subnet.Available(ipFamily) {
			subnets = append(subnets, subnet)
		}
	}

	if subnets.Len() == 0 {
		m.RecordSubnetEvent(v1.EventTypeWarning, tracing.EventNoAvailableSubnet,
			fmt.Sprintf("No available subnet in %s", m.zoneId))
		return nil
	}
	sort.Sort(sort.Reverse(subnets))
	return subnets[0]
}

func (m *subnetManager) DisableSubnet(subnetId string) {
	if subnet, exist := m.podSubnets[subnetId]; exist {
		subnet.DisableSubnet()
	}
}

func (m *subnetManager) EnableSubnet(subnetId string) {
	if subnet, exist := m.podSubnets[subnetId]; exist {
		subnet.EnableSubnet()
	}
}

func NewPodSubnetManager(zoneId, vpcId string, client ec2.APIGroupSubnet, options ...PodSubnetManagerOption) (SubnetManager, error) {
	if zoneId == "" {
		return nil, fmt.Errorf("invaild zoneId %s", zoneId)
	}

	if vpcId == "" {
		return nil, fmt.Errorf("invaild vpcId %s", vpcId)
	}
	if client == nil {
		return nil, fmt.Errorf("client of subnet open api is nil")
	}
	m := &subnetManager{
		zoneId:          zoneId,
		vpcId:           vpcId,
		podSubnets:      make(map[string]*PodSubnet),
		legacyPodSubnet: make(map[string]*PodSubnet),
		apiClient:       client,
		config:          DefaultPodSubnetManagerConfig(),
	}

	for _, option := range options {
		option(m.config)
	}
	return m, nil
}

func removeDuplicateElement(origin []string) []string {
	result := make([]string, 0, len(origin))
	temp := map[string]struct{}{}
	for _, item := range origin {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
