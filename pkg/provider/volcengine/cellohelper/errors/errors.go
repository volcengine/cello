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
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/volcengine-go-sdk/volcengine/response"

	"github.com/volcengine/cello/pkg/tracing"
)

const (
	InvalidParameter = "InvalidParameter"
	MissingParameter = "MissingParameter"
	InternalError    = "InternalError"

	InvalidVpcInvalidStatus          = "InvalidVpc.InvalidStatus"
	InvalidEniInvalidStatus          = "InvalidEni.InvalidStatus"
	InvalidEniIdNotFound             = "InvalidEniId.NotFound"
	InvalidSubnetNotFound            = "InvalidSubnet.NotFound"
	InvalidEniInstanceMismatch       = "InvalidEni.InstanceMismatch"
	InvalidSubnetDisableIpv6         = "InvalidSubnet.DisableIpv6"
	LimitExceededPrivateIpsPerEni    = "LimitExceeded.PrivateIpsPerEni"
	LimitExceededIpv6AddressesPerEni = "LimitExceeded.Ipv6AddressesPerEni"
	LimitExceededEnisPerInstance     = "LimitExceeded.EnisPerInstance"
	QuotaExceededSecurityGroupIp     = "QuotaExceeded.SecurityGroupIp"
	QuotaExceededEniSecurityGroup    = "QuotaExceeded.EniSecurityGroup"
	QuotaExceededEni                 = "QuotaExceeded.Eni"
	InvalidPrivateIpMalformed        = "InvalidPrivateIp.Malformed"
	InvalidIpv6Malformed             = "InvalidIpv6.Malformed"
	InsufficientIpInSubnet           = "InsufficientIpInSubnet"
	AccountFlowLimitExceeded         = "AccountFlowLimitExceeded"
	FlowLimitExceeded                = "FlowLimitExceeded"
)

// APIRequestError is interface of openapi sdk error wrapper.
type APIRequestError interface {
	error
	ErrorCodeN() int
	ErrorCode() string
	Message() string
	RequestId() string
}

// APIRequestErr is error wrapper of openapi sdk.
type APIRequestErr struct {
	sdkErr    error
	requestId string
	codeN     int
	code      string
	message   string
}

func (e *APIRequestErr) Error() string {
	var info string
	if e.sdkErr != nil {
		info = "sdkErr: " + e.sdkErr.Error()
	}

	if e.message != "" {
		return fmt.Sprintf("apiErr: %s(%s [%d]) RequestId %s", e.message, e.code, e.codeN, e.requestId)
	} else {
		return info
	}
}

func (e *APIRequestErr) ErrorCodeN() int {
	return e.codeN
}

func (e *APIRequestErr) ErrorCode() string {
	return e.code
}

func (e *APIRequestErr) Message() string {
	return e.message
}

func (e *APIRequestErr) RequestId() string {
	return e.requestId
}

// NewAPIRequestErr wrap openapi error and sdk error.
func NewAPIRequestErr(responseMetadata *response.ResponseMetadata, sdkErr error) APIRequestError {
	err := &APIRequestErr{
		sdkErr: sdkErr,
	}
	if responseMetadata != nil && responseMetadata.Error != nil {
		err.requestId = responseMetadata.RequestId
		err.codeN = responseMetadata.Error.CodeN
		err.code = responseMetadata.Error.Code
		err.message = responseMetadata.Error.Message
	}
	return err
}

func ErrEqual(errCode string, err error) bool {
	respErr, ok := err.(APIRequestError)
	if ok {
		return respErr.ErrorCode() == errCode
	}
	return false
}

// BackoffErrWrapper wrap backoff error and true error of internal.
func BackoffErrWrapper(backErr, realErr error) error {
	var message string
	if backErr != nil {
		if errors.Is(backErr, wait.ErrWaitTimeout) {
			message = backErr.Error()
		} else {
			return backErr
		}
	} else {
		return nil // backErr==nil means success, ignore realErr
	}
	if realErr != nil {
		if message != "" {
			message = fmt.Sprintf("%s due to %s", message, realErr.Error())
		} else {
			return realErr
		}
	}
	if message == "" {
		return nil
	}
	return errors.New(message)
}

// OpenApiErrCodeChain used while assert errors with error code.
type OpenApiErrCodeChain struct {
	errs []string
}

func (c *OpenApiErrCodeChain) WithPublicErrCodes() *OpenApiErrCodeChain {
	c.errs = append(c.errs, InvalidParameter, MissingParameter, InternalError)
	return c
}

func (c *OpenApiErrCodeChain) WithFlowLimitExceeded() *OpenApiErrCodeChain {
	c.errs = append(c.errs, FlowLimitExceeded, AccountFlowLimitExceeded)
	return c
}

func (c *OpenApiErrCodeChain) WithErrCodes(codes ...string) *OpenApiErrCodeChain {
	c.errs = append(c.errs, codes...)
	return c
}

// ErrChainEqual return ture if err is equal to any errCode in OpenApiErrCodeChain.
func (c *OpenApiErrCodeChain) ErrChainEqual(err error) bool {
	for _, errCode := range c.errs {
		if ErrEqual(errCode, err) {
			return true
		}
	}
	return false
}

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
	respErr, ok := err.(APIRequestError)
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

// define some errors that need to be propagated upwards

var (
	ErrNotFound                 = errors.New("not found")
	ErrHalfwayFailed            = errors.New("process halfway failed")
	ErrInvalidDeletionPrimaryIP = errors.New("ip is primary, deletion invalid")
)
