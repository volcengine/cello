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
	// RpcLatency the latency of rpc call.
	RpcLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: metricsSubsystem,
			Name:      "rpc_latency_ms",
			Help:      "cello rpc call latency in ms",
			Buckets:   []float64{50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 26600, 27600, 29600, 33600, 41600, 57600, 89600, 110000, 120000},
		},
		[]string{"rpc_api", "error"},
	)

	// ResourceManagerErr error counter of resource manager.
	ResourceManagerErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: metricsSubsystem,
			Name:      "resource_manager_error_count",
			Help:      "The number of errors encountered in eni manager",
		},
		[]string{"fn", "error"},
	)

	// SubSysErr error counter of sub system.
	SubSysErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: metricsSubsystem,
			Name:      "sub_sys_error_count",
			Help:      "The number of errors encountered in sub sys",
		},
		[]string{"subsys", "code"},
	)
)

func ResourceManagerErrInc(fn string, err error) {
	ResourceManagerErr.WithLabelValues(fn, err.Error()).Inc()
}

func SubSysErrInc(subsys string, code string) {
	SubSysErr.WithLabelValues(subsys, code).Inc()
}
