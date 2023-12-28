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

package metadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/metrics"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/version"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "metadata"})

const (
	Endpoint = "http://100.96.0.96/volcstack/latest"
)

var metadataTimeout = time.Second * 5

type EC2Metadata struct {
	endpoint string
	client   *http.Client
}

func New() *EC2Metadata {
	endpoint := os.Getenv("METADATA_ENDPOINT")
	if endpoint == "" {
		endpoint = Endpoint
	}
	return &EC2Metadata{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: metadataTimeout,
		},
	}
}

// GetMetadata get information from metadata by path.
func (c *EC2Metadata) GetMetadata(ctx context.Context, sign, path string) (info string, err error) {
	var req *http.Request
	var resp *http.Response
	info = ""
	url := fmt.Sprintf("%s/%s", c.endpoint, path)

	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("Call metadata failed, path: %s, err: %v", url, err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventMetadataServiceAbnormal, fmtErr)
			log.ErrorS(err, "Call metadata failed", "path", url)
		}
	}()

	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err != nil {
		return
	}
	// Set User-Agent
	req.Header.Set("User-Agent", version.UserAgent())

	startTime := time.Now()
	if resp, err = c.client.Do(req); err != nil {
		metrics.MetadataStatisticRecord(sign, apiErr.ClientErrHttpCode, apiErr.ClientErr)
		return
	}
	metrics.MetadataLatencyRecord(sign, startTime)

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	metrics.MetadataStatisticRecord(sign, resp.StatusCode, apiErr.RequestSuccess)
	if resp.StatusCode != http.StatusOK {
		err = errors.New(fmt.Sprintf("HttpRequestStatus: %d", resp.StatusCode))
		return
	}
	var respBytes []byte
	if respBytes, err = io.ReadAll(resp.Body); err != nil {
		return
	}
	info = string(respBytes)
	return
}
