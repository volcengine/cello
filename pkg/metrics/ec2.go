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
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
)

var (
	// OpenAPILatency latency of openapi call.
	OpenAPILatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "openapi_latency_ms",
			Help: "cello openapi call latency in ms",
		},
		[]string{"api", "error", "code", "requestId"},
	)

	// OpenAPIErr error counter of openapi call.
	OpenAPIErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openapi_error_count",
			Help: "The number of times openapi returns an error",
		},
		[]string{"api", "error", "code", "requestId"},
	)

	// MetadataLatency latency of metadata call.
	MetadataLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "metadata_latency_ms",
			Help: "cello metadata call latency in ms",
		},
		[]string{"metadata", "error", "status"},
	)

	// MetadataErr error counter of metadata call.
	MetadataErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "metadata_error_count",
			Help: "The number of times metadata returns an error",
		},
		[]string{"metadata", "error"},
	)
)

// OpenAPIErrInc help to increment count of OpenAPIErr.
func OpenAPIErrInc(api string, err error) {
	OpenAPIErr.With(prometheus.Labels{"api": api, "error": err.Error(), "code": CelloReqErrCode(err), "requestId": CelloReqId(err)}).Inc()
}

// MetadataErrInc help to increment count of MetadataErr.
func MetadataErrInc(metadata string, err error) {
	MetadataErr.With(prometheus.Labels{"metadata": metadata, "error": err.Error()}).Inc()
}

// CelloReqId return requestId of api request.
func CelloReqId(err error) string {
	if err == nil {
		return ""
	}
	var aer apiErr.APIRequestError
	if errors.As(err, &aer) {
		return aer.RequestId()
	}
	return ""
}

// CelloReqErrCode return error code of api request.
func CelloReqErrCode(err error) string {
	if err == nil {
		return ""
	}
	var aer apiErr.APIRequestError
	if errors.As(err, &aer) {
		return aer.ErrorCode()
	}
	return err.Error() // Unknown err code
}
