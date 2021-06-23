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

package pool

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/volcengine/cello/pkg/metrics"
)

// Status basic information of pool.
type Status struct {
	TargetMin       int
	Target          int
	MaxCap          int
	MaxCapProbe     bool
	MonitorInterval time.Duration
	Total           int
	Available       int
	Short           int
	Over            int
}

// Config of pool.
type Config struct {
	// Name of pool
	Name string

	// Type of resource in pool
	Type string

	// TargetMin minimum number of all resources(contains the used) in pool
	TargetMin int

	// Target cache target of resource in pool
	Target int

	// MaxCap max capacity of pool
	MaxCap int

	// MaxCapProbe if enable the capacity detection function
	MaxCapProbe bool

	// MonitorInterval period of pool monitor
	MonitorInterval time.Duration

	// GCProtectPeriod protect period of resource while gc action
	GCProtectPeriod time.Duration

	// Factory to create resource in pool
	Factory ObjectFactory

	// PreStart run before the pool starts working
	PreStart ResourcePoolHook
}

func (c *Config) newPoolConfigInner() poolConfigInner {
	return poolConfigInner{
		configLock:      sync.RWMutex{},
		targetMin:       c.TargetMin,
		target:          c.Target,
		maxCap:          c.MaxCap,
		maxCapProbe:     c.MaxCapProbe,
		monitorInterval: c.MonitorInterval,
		gcProtectPeriod: c.GCProtectPeriod,

		metricsMaxCap:   metrics.ResourcePoolMaxCap.WithLabelValues(c.Name, c.Type),
		metricTarget:    metrics.ResourcePoolTarget.WithLabelValues(c.Name, c.Type),
		metricTargetMin: metrics.ResourcePoolTargetMin.WithLabelValues(c.Name, c.Type),
	}
}

type poolConfigInner struct {
	configLock      sync.RWMutex
	targetMin       int
	target          int
	maxCap          int
	maxCapProbe     bool
	monitorInterval time.Duration
	gcProtectPeriod time.Duration

	metricsMaxCap   prometheus.Gauge
	metricTargetMin prometheus.Gauge
	metricTarget    prometheus.Gauge
}

func (p *poolImpl) getMaxCap() int {
	p.configLock.RLock()
	defer p.configLock.RUnlock()
	var maxCap int

	if p.maxCapProbe {
		maxCap = p.factory.GetResourceLimit()
	} else {
		maxCap = p.maxCap
	}
	p.metricsMaxCap.Set(float64(maxCap))
	return maxCap
}

func (p *poolImpl) getMonitorInterval() time.Duration {
	p.configLock.RLock()
	defer p.configLock.RUnlock()
	return p.monitorInterval
}

func (p *poolImpl) getTarget() int {
	p.configLock.RLock()
	defer p.configLock.RUnlock()
	return p.target
}

func (p *poolImpl) setTarget(t int) {
	p.configLock.Lock()
	defer p.configLock.Unlock()
	p.target = t
}

func (p *poolImpl) getTargetMin() int {
	p.configLock.RLock()
	defer p.configLock.RUnlock()
	return p.targetMin
}

func (p *poolImpl) setTargetMin(t int) {
	p.configLock.Lock()
	defer p.configLock.Unlock()
	p.targetMin = t
}

func (p *poolImpl) getMaxCapProbe() bool {
	p.configLock.RLock()
	defer p.configLock.RUnlock()
	return p.maxCapProbe
}

func (p *poolImpl) getGcProtectPeriod() time.Duration {
	p.configLock.RLock()
	defer p.configLock.RUnlock()
	return p.gcProtectPeriod
}
