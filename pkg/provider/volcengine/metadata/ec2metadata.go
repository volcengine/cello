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
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/utils/logger"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "metadata"})

const (
	metadataURL = "http://100.96.0.96/volcstack/latest"
)

var metadataTimeout = time.Second * 5

type EC2Metadata struct {
	*http.Client
}

func New() *EC2Metadata {
	return &EC2Metadata{
		&http.Client{
			Timeout: metadataTimeout,
		},
	}
}

// GetMetadata get information from metadata by path.
func (c *EC2Metadata) GetMetadata(ctx context.Context, path string) (info string, err error) {
	var req *http.Request
	var resp *http.Response
	info = ""
	url := fmt.Sprintf("%s/%s", metadataURL, path)

	defer func() {
		if err != nil {
			fmtErr := fmt.Sprintf("Call metadata failed, path: %s, err: %v", url, err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventMetadataServiceAbnormal, fmtErr)
			log.Errorf(fmtErr)
		}
	}()

	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err != nil {
		return
	}

	if resp, err = c.Do(req); err != nil {
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		err = errors.New(fmt.Sprintf("HttpRequestStatus: %d", resp.StatusCode))
		return
	}
	var respBytes []byte
	if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return
	}
	info = string(respBytes)
	return
}
