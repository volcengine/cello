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

package cidr

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
)

type Config struct {
	DataDir string                         `json:"dataDir"`
	Ranges  map[string]*allocator.RangeSet `json:"ranges,omitempty"`
}

func LoadConfigFromFile(path string) (*Config, error) {
	c := Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config failed, %v", err)
	}
	err = json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	err = validateConfig(&c)
	if err != nil {
		return nil, fmt.Errorf("failed to validate config")
	}
	return &c, nil
}

func validateConfig(c *Config) error {
	err := os.MkdirAll(c.DataDir, 0755)
	if err != nil {
		return err
	}

	if c.Ranges == nil {
		c.Ranges = map[string]*allocator.RangeSet{}
	}

	for id, v := range c.Ranges {
		if err = v.Canonicalize(); err != nil {
			return err
		}
		// check range start and end
		for _, r := range []allocator.Range(*v) {
			if ip.Cmp(r.RangeEnd, r.RangeStart) < 0 {
				return fmt.Errorf("start not smaller than end of range %s in %s", v.String(), id)
			}
		}
	}

	return nil
}
