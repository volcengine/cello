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

package errors_test

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
)

var (
	normalMetadata = response.ResponseMetadata{
		RequestId: "202312345678",
		Action:    "MockCall",
		Version:   "2023-1-1",
		Service:   "volcengine",
		Region:    "cn-mock",
		HTTPCode:  200,
		Error:     nil,
	}

	abnormalMetadata = &response.ResponseMetadata{
		RequestId: "202312345678",
		Action:    "MockCall",
		Version:   "2023-1-1",
		Service:   "volcengine",
		Region:    "cn-mock",
		HTTPCode:  404,
		Error: &response.Error{
			CodeN:   123,
			Code:    errors.InternalError,
			Message: "some error occurred",
		},
	}
)

var _ = Describe("Errors", func() {
	It("should return no err if args all nil", func() {
		status := errors.NewAPIRequestStatus(nil, nil)
		Expect(status).To(Equal(&errors.APIRequestStat{}))
		Expect(status.GetError()).NotTo(HaveOccurred())
		Expect(status.Error()).To(Equal(""))
	})

	It("should return no err if no error occurred", func() {
		status := errors.NewAPIRequestStatus(&normalMetadata, nil)
		Expect(status.HttpCode()).To(Equal(normalMetadata.HTTPCode))
		Expect(status.GetError()).NotTo(HaveOccurred())
		Expect(status.ErrorCode()).To(Equal(errors.RequestSuccess))
		Expect(status.RequestId()).To(Equal(normalMetadata.RequestId))
		Expect(status.Error()).To(Equal(""))
	})

	It("should return client error if client send request failed", func() {
		clientErr := fmt.Errorf("network maybe abnormal")
		status := errors.NewAPIRequestStatus(nil, clientErr)
		Expect(status.HttpCode()).To(Equal(errors.ClientErrHttpCode))
		Expect(status.GetError()).To(HaveOccurred())
		Expect(status.ErrorCode()).To(Equal(errors.ClientErr))
		Expect(status.RequestId()).To(Equal(""))

		Expect(status.Error()).To(ContainSubstring(clientErr.Error()))
		Expect(status.Error()).To(ContainSubstring(strconv.Itoa(errors.ClientErrHttpCode)))
	})

	Context("should focus on response if return", func() {
		It("should return error from response if it is not nil", func() {
			clientErr := fmt.Errorf("unlikely error")
			status := errors.NewAPIRequestStatus(abnormalMetadata, clientErr)
			Expect(status.HttpCode()).To(Equal(abnormalMetadata.HTTPCode))
			Expect(status.GetError()).To(HaveOccurred())
			Expect(status.ErrorCode()).To(Equal(abnormalMetadata.Error.Code))
			Expect(status.RequestId()).To(Equal(abnormalMetadata.RequestId))

			Expect(strings.Contains(status.Error(), clientErr.Error())).To(BeFalse())
			Expect(status.ErrorCodeN()).To(Equal(abnormalMetadata.Error.CodeN))
			Expect(status.Message()).To(Equal(abnormalMetadata.Error.Message))
		})
	})

	Describe("test func ErrEqual", func() {
		Context("error is not APIRequestErr", func() {
			err := fmt.Errorf("some error")
			It("should return false", func() {
				Expect(errors.ErrEqual("notCare", err)).To(BeFalse())
			})
		})
		Context("error is APIRequestErr", func() {
			status := errors.NewAPIRequestStatus(abnormalMetadata, fmt.Errorf("notCare"))
			It("should return true if errCode equal", func() {
				Expect(errors.ErrEqual(status.ErrorCode(), status.GetError())).To(BeTrue())
			})
			It("should return false if errCode not equal", func() {
				Expect(errors.ErrEqual("notCare", status.GetError())).To(BeFalse())
			})

		})
	})

	Context("test func GetAPIRequestStat", func() {
		It("should return {0, '', ''} if args all nil", func() {
			status := errors.NewAPIRequestStatus(nil, nil)
			Expect(status.HttpCode()).To(Equal(0))
			Expect(status.ErrorCode()).To(Equal(""))
			Expect(status.RequestId()).To(Equal(""))
		})

		It("should return {200, RequestSuccess, *requestId*} if no error", func() {
			status := errors.NewAPIRequestStatus(&normalMetadata, nil)
			Expect(status.HttpCode()).To(Equal(normalMetadata.HTTPCode))
			Expect(status.ErrorCode()).To(Equal(errors.RequestSuccess))
			Expect(status.RequestId()).To(Equal(normalMetadata.RequestId))
		})

		It("should return {*httpCode*, 'ErrorCode', *requestId*} if response has error", func() {
			status := errors.NewAPIRequestStatus(abnormalMetadata, fmt.Errorf("not care"))
			Expect(status.HttpCode()).To(Equal(abnormalMetadata.HTTPCode))
			Expect(status.ErrorCode()).To(Equal(abnormalMetadata.Error.Code))
			Expect(status.RequestId()).To(Equal(abnormalMetadata.RequestId))
		})

		It("should return {5000, ClientError, ''} if client send request error", func() {
			status := errors.NewAPIRequestStatus(nil, fmt.Errorf("send failed"))
			Expect(status.HttpCode()).To(Equal(errors.ClientErrHttpCode))
			Expect(status.ErrorCode()).To(Equal(errors.ClientErr))
			Expect(status.RequestId()).To(Equal(""))
		})
	})

	Context("test BackoffErrWrapper", func() {
		It("test backoff failed and no real error", func() {
			err := errors.BackoffErrWrapper(wait.ErrWaitTimeout, nil)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(wait.ErrWaitTimeout.Error()))
			backErr := fmt.Errorf("some error")
			err = errors.BackoffErrWrapper(backErr, nil)
			Expect(err).To(Equal(backErr))
		})

		It("test backoff failed with real error", func() {
			err := errors.BackoffErrWrapper(wait.ErrWaitTimeout, fmt.Errorf("real error"))
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("due to"))
		})

		It("test no backoff error with real error", func() {
			err := errors.BackoffErrWrapper(nil, fmt.Errorf("real error"))
			Expect(err).To(BeNil())
		})
	})

	Context("test OpenApiErrCodeChain", func() {
		It("test OpenApiErrCodeChain", func() {
			chain := &errors.OpenApiErrCodeChain{}
			chain.WithPublicErrCodes().WithFlowLimitExceeded().WithErrCodes(errors.InsufficientIpInSubnet)
			testMetadata := &response.ResponseMetadata{
				RequestId: "RequestId",
				Action:    "Action",
				Version:   "Version",
				Service:   "Service",
				Region:    "Region",
				HTTPCode:  404,
				Error: &response.Error{
					CodeN:   0,
					Code:    errors.InsufficientIpInSubnet,
					Message: "some errors",
				},
			}
			Expect(chain.ErrChainEqual(errors.NewAPIRequestStatus(testMetadata, nil).GetError())).To(BeTrue())
			testMetadata.Error.Code = errors.InvalidEniInstanceMismatch
			Expect(chain.ErrChainEqual(errors.NewAPIRequestStatus(testMetadata, nil).GetError())).To(BeFalse())
		})
	})

})
