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

package errors

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/tracing"
)

type EventInfoField struct {
	Key   string
	Value interface{}
}

func (f *EventInfoField) String() string {
	return fmt.Sprintf("%s=%v", f.Key, f.Value)
}

var (
	cantRetryErrEventLimiter *rate.Limiter
	flowLimitEventLimiter    *rate.Limiter
)

func AllowRecordErrEvent() bool {
	if cantRetryErrEventLimiter == nil {
		return true
	}
	return cantRetryErrEventLimiter.Allow()
}

func AllowRecordFlowLimitEvent() bool {
	if flowLimitEventLimiter == nil {
		return true
	}
	return flowLimitEventLimiter.Allow()
}

// RecordOpenAPIErrEvent report Event with message according to APIRequestError,
// if message is "", a default message will be used.
func RecordOpenAPIErrEvent(err error, fields ...EventInfoField) {
	var respErr APIRequestError
	ok := errors.As(err, &respErr)
	if !ok {
		return
	}
	errCode := respErr.ErrorCode()

	fieldsInfo := ""
	for _, field := range fields {
		fieldsInfo += field.String()
		fieldsInfo += " "
	}
	fmtInfo := fmt.Sprintf("%s, %s", errCode, fieldsInfo)
	if respErr.RequestId() != "" {
		fmtInfo = fmt.Sprintf("%s RequestId: %s", fmtInfo, respErr.RequestId())
	}

	if strings.HasPrefix(errCode, "QuotaExceeded") ||
		strings.HasPrefix(errCode, "LimitExceeded") {
		if AllowRecordErrEvent() {
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventVpcResourceQuotaExceeded, fmtInfo)
		}
	}

	switch errCode {
	case InsufficientIpInSubnet:
		if AllowRecordErrEvent() {
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventInsufficientIpInSubnet, fmtInfo)
		}
	case FlowLimitExceeded, AccountFlowLimitExceeded:
		if AllowRecordFlowLimitEvent() {
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventOpenApiFlowLimit, fmtInfo)
		}
	}
}

func init() {
	if flowLimitEventLimiter == nil {
		flowLimitEventLimiter = rate.NewLimiter(2, 2)
	}
	if cantRetryErrEventLimiter == nil {
		cantRetryErrEventLimiter = rate.NewLimiter(5, 5)
	}
}
