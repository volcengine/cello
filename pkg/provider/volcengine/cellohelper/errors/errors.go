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

	"github.com/pkg/errors"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	RequestSuccess = ""

	// ClientErr means client can not send request
	ClientErr         = "ClientError"
	ClientErrHttpCode = 5000

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

// APIRequestStat is error wrapper of openapi sdk.
type APIRequestStat struct {
	clientErr error  // error from client
	httpCode  int    // httpCode from metadata of api response or from client
	requestId string // requestId from metadata of api response
	codeN     int    // codeN from error of api response
	code      string // code from error of api response
	message   string // message from error of api response
}

func (e *APIRequestStat) Error() string {
	if e.clientErr != nil {
		return fmt.Sprintf("client error: %s httpCode: %d", e.clientErr.Error(), e.httpCode)
	}

	if e.message != "" {
		return fmt.Sprintf("%s(%s [%d]) requestId %s hpptCode %d", e.message, e.code, e.codeN, e.requestId, e.httpCode)
	}
	return ""
}

func (e *APIRequestStat) HttpCode() int {
	return e.httpCode
}

func (e *APIRequestStat) ErrorCodeN() int {
	return e.codeN
}

func (e *APIRequestStat) ErrorCode() string {
	return e.code
}

func (e *APIRequestStat) Message() string {
	return e.message
}

func (e *APIRequestStat) RequestId() string {
	return e.requestId
}

// NewAPIRequestStatus wrap error and info of response.
func NewAPIRequestStatus(responseMetadata *response.ResponseMetadata, cErr error) *APIRequestStat {
	// response first
	if responseMetadata != nil && responseMetadata.RequestId != "" { // get response
		stat := &APIRequestStat{
			clientErr: nil,
			httpCode:  responseMetadata.HTTPCode,
			requestId: responseMetadata.RequestId,
			code:      RequestSuccess,
		}
		if responseMetadata.Error != nil {
			stat.codeN = responseMetadata.Error.CodeN
			stat.code = responseMetadata.Error.Code
			stat.message = responseMetadata.Error.Message
		}
		return stat
	} else if cErr != nil {
		return &APIRequestStat{
			clientErr: cErr,
			httpCode:  ClientErrHttpCode,
			code:      ClientErr,
		}
	}
	return &APIRequestStat{}
}

func (e *APIRequestStat) GetError() APIRequestError {
	if e.code != RequestSuccess {
		return e
	}
	return nil
}

func ErrEqual(errCode string, err error) bool {
	var respErr APIRequestError
	ok := errors.As(err, &respErr)
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

// define some errors that need to be propagated upwards

var (
	ErrNotFound                 = errors.New("not found")
	ErrHalfwayFailed            = errors.New("process halfway failed")
	ErrInvalidDeletionPrimaryIP = errors.New("ip is primary, deletion invalid")
)
