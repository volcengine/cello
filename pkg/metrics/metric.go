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
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/volcengine/cello/pkg/utils/logger"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "metrics"})

const (
	// Environment variable to disable the metrics endpoint on 61678.
	envDisableMetrics = "CELLO_DISABLE_METRICS"
)

// ServeMetrics sets up cello metrics.
func ServeMetrics(serveMux *http.ServeMux) {
	if disableMetrics() {
		log.InfoS("Metrics endpoint disabled")
		return
	}

	log.InfoS("Register metrics server")
	serveMux.Handle("/metrics", promhttp.Handler())
}

// disableMetrics returns true if we should disable metrics.
func disableMetrics() bool {
	return getEnvBoolWithDefault(envDisableMetrics, false)
}

func getEnvBoolWithDefault(envName string, def bool) bool {
	if strValue := os.Getenv(envName); strValue != "" {
		parsedValue, err := strconv.ParseBool(strValue)
		if err == nil {
			return parsedValue
		}
		log.ErrorS(err, "Failed to parse, using default", "envName", envName)
	}
	return def
}

var prometheusRegistered = false

func PrometheusRegister() {
	if prometheusRegistered {
		return
	}

	prometheus.MustRegister(RpcLatency)
	prometheus.MustRegister(OpenAPILatency)
	prometheus.MustRegister(OpenAPIStatistic)
	prometheus.MustRegister(MetadataLatency)
	prometheus.MustRegister(MetadataStatistic)

	prometheus.MustRegister(ResourcePoolMaxCap)
	prometheus.MustRegister(ResourcePoolTarget)
	prometheus.MustRegister(ResourcePoolTargetMin)
	prometheus.MustRegister(ResourcePoolTotal)
	prometheus.MustRegister(ResourcePoolAvailable)

	prometheusRegistered = true
}

// MsSince returns milliseconds since start.
func MsSince(start time.Time) float64 {
	return float64(time.Since(start) / time.Millisecond)
}
