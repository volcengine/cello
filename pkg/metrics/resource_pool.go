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

package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// ResourcePoolMaxCap Gauge of resource pool maximum capacity.
	ResourcePoolMaxCap = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "resource_pool_max_cap",
			Help: "The max capacity of resource pool"},
		[]string{"name", "type"},
	)

	// ResourcePoolTarget Gauge of resource pool target.
	ResourcePoolTarget = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "resource_pool_target",
			Help: "The cache target of resource pool"},
		[]string{"name", "type"},
	)

	// ResourcePoolTargetMin Gauge of resource pool targetMin.
	ResourcePoolTargetMin = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "resource_pool_target_min",
			Help: "The min cache target of resource pool"},
		[]string{"name", "type"},
	)

	// ResourcePoolTotal Gauge of total resources in resource pool.
	ResourcePoolTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "resource_pool_total",
			Help: "The total number of resource in pool"},
		[]string{"name", "type"},
	)

	// ResourcePoolAvailable Gauge of available resources in resource pool.
	ResourcePoolAvailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "resource_pool_available",
			Help: "The available number of resource in pool"},
		[]string{"name", "type"},
	)
)
