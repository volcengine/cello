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

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
)

type Config struct {
	Mode    string                        `json:"mode,omitempty"`
	DataDir string                        `json:"dataDir"`
	Ranges  map[string]allocator.RangeSet `json:"ranges,omitempty"`

	Hook func() (map[string]allocator.RangeSet, error) `json:"-"`
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
	return &c, nil
}

func PrepareConfig(c *Config) error {
	err := os.MkdirAll(c.DataDir, 0755)
	if err != nil {
		return err
	}

	if c.Ranges == nil {
		c.Ranges = map[string]allocator.RangeSet{}
	}

	if c.Hook != nil {
		ranges, inErr := c.Hook()
		if inErr != nil {
			return inErr
		}
		// merge
		for k, v := range ranges {
			c.Ranges[k] = append(c.Ranges[k], v...)
		}
	}

	for _, v := range c.Ranges {
		if err = v.Canonicalize(); err != nil {
			return err
		}
	}

	return nil
}
