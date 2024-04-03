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

package metadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/metrics"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/version"
)

const (
	DefaultURL     = "http://100.96.0.96/latest"
	DefaultTimeout = 10 * time.Second
)

type Getter interface {
	Get(ctx context.Context, sign string, path string) ([]byte, error)
}

// InterfaceInfo represents NIC information that metadata service would return
type InterfaceInfo struct {
	NetworkInterfaceID string   `json:"NetworkInterfaceId,omitempty"`
	PrimaryIPAddress   string   `json:"PrimaryIpAddress,omitempty"`
	Gateway            string   `json:"Gateway,omitempty"`
	SubnetID           string   `json:"SubnetId,omitempty"`
	SubnetCidrBlock    string   `json:"SubnetCidrBlock,omitempty"`
	PrivateIpv4s       string   `json:"PrivateIpv4s,omitempty"`
	PrivateIPAddresses []string `json:"PrivateIpAddresses,omitempty"`
}

type Client struct {
	endpoint   string
	httpClient *http.Client
}

func NewMetadataWithConfig(url string, timeout time.Duration) *Client {
	return &Client{
		endpoint: url,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// NewClient creates a volcengine metadata client with default url: "http://100.96.0.96/volcstack/latest/"
// and default timeout 10 seconds.
func NewClient() *Client {
	return NewMetadataWithConfig(DefaultURL, DefaultTimeout)
}

// Get information from metadata by path.
func (client *Client) Get(ctx context.Context, sign string, path string) ([]byte, error) {
	var err error
	endpoint, err := url.JoinPath(client.endpoint, path)
	if err != nil {
		return nil, fmt.Errorf("failed to join url path %v", path)
	}

	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("Call metadata failed, path: %s, err: %v", endpoint, err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventMetadataServiceAbnormal, fmtErr)
			log.ErrorS(err, "Call metadata failed", "path", endpoint)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request %v err: %w", *req, err)
	}
	req.Header.Set("User-Agent", version.UserAgent())

	startTime := time.Now()
	resp, err := client.httpClient.Do(req)
	if err != nil {
		metrics.MetadataStatisticRecord(sign, apiErr.ClientErrHttpCode, apiErr.ClientErr)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WarnS("Failed to close metadata response", "error", err)
		}
	}(resp.Body)
	metrics.MetadataLatencyRecord(sign, startTime)

	metrics.MetadataStatisticRecord(sign, resp.StatusCode, apiErr.RequestSuccess)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request metadata %v code: %d", *req, resp.StatusCode)

	}
	var respBytes []byte
	if respBytes, err = io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response error %w", err)
	}
	return respBytes, nil
}
