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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/volcengine/cello/pkg/daemon"
)

func debugClient() *http.Client {
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", daemon.DefaultDebugSocketPath)
			},
		},
	}
	return &httpc
}

type AdditionArg struct {
	Key   string
	Value string
}

func debugClientGet(url string, message interface{}, args ...AdditionArg) error {
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	query := request.URL.Query()
	for _, arg := range args {
		query.Add(arg.Key, arg.Value)
	}
	request.URL.RawQuery = query.Encode()
	resp, err := debugClient().Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response: %+v", resp)
	}
	if message == nil {
		return nil
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read resp body err %s", err.Error())
	}

	err = json.Unmarshal(bodyText, &message)
	if err != nil {
		return fmt.Errorf("unmarshal to %v err, %v", message, err.Error())
	}
	return nil
}

func PrettyJson(obj interface{}) string {
	if obj == nil {
		return ""
	}

	bs, _ := json.Marshal(obj)
	var out bytes.Buffer
	err := json.Indent(&out, bs, "", "\t")
	if err != nil {
		return ""
	}
	return out.String()
}
