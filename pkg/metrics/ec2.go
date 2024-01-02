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

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// OpenAPILatency volcengine open api latency
	OpenAPILatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: metricsSubsystem,
			Name:      "openapi_latency_ms",
			Help:      "volcengine openapi latency in ms",
			Buckets:   []float64{50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 13800, 14800, 16800, 20800, 28800, 44800},
		},
		[]string{"api"},
	)

	// OpenAPIStatistic counter of volcengine openapi call.
	OpenAPIStatistic = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: metricsSubsystem,
			Name:      "openapi_statistic",
			Help:      "The statistic of openapi call",
		},
		[]string{"api", "httpCode", "errCode"},
	)

	MetadataLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: metricsSubsystem,
			Name:      "metadata_latency_ms",
			Help:      "volcengine metadata latency in ms",
			Buckets:   []float64{50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 13800, 14800, 16800, 20800, 28800, 44800},
		},
		[]string{"url"},
	)

	// MetadataStatistic counter of volcengine openapi call.
	MetadataStatistic = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: metricsSubsystem,
			Name:      "metadata_statistic",
			Help:      "The statistic of metadata call",
		},
		[]string{"url", "httpCode", "errCode"},
	)
)

// OpenAPILatencyRecord record latency of api
func OpenAPILatencyRecord(api string, startTime time.Time) {
	OpenAPILatency.WithLabelValues(api).Observe(float64(time.Since(startTime).Milliseconds()))
}

// OpenAPIStatisticRecord record statistic of api call
func OpenAPIStatisticRecord(api string, httpCode int, errCode string) {
	OpenAPIStatistic.WithLabelValues(api, strconv.Itoa(httpCode), errCode).Inc()
}

// MetadataLatencyRecord record latency of metadata
func MetadataLatencyRecord(url string, startTime time.Time) {
	MetadataLatency.WithLabelValues(url).Observe(float64(time.Since(startTime).Milliseconds()))
}

// MetadataStatisticRecord record statistic of metadata call
func MetadataStatisticRecord(url string, httpCode int, errCode string) {
	MetadataStatistic.WithLabelValues(url, strconv.Itoa(httpCode), errCode).Inc()
}
