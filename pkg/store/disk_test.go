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

package store

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockObj struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func newStorage() (Interface, error) {
	return NewDiskStorage("test1", "./test.db", json.Marshal, func(bytes []byte) (interface{}, error) {
		obj := &mockObj{}
		err := json.Unmarshal(bytes, obj)
		if err != nil {
			return nil, err
		}
		return *obj, nil
	})
}

func TestDistStore(t *testing.T) {
	tests := []struct {
		description    string
		useDiskBackend bool
	}{
		{"Test disk storage", true},
		{"Test cache storage", true},
	}
	objs := []mockObj{
		{"t0", "v0"},
		{"t1", "v1"},
		{"t2", "v2"},
		{"t3", "v4"},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			defer func() {
				_ = os.Remove("./test.db")
			}()

			db, err := newStorage()
			if err != nil {
				t.Errorf("NewDiskStorage err %s", err)
			}

			// Put
			for i := range objs {
				err = db.Put(objs[i].Name, objs[i])
				if err != nil {
					t.Errorf("db Put err %s", err)
				}
			}
			// Reload data from disk.
			if test.useDiskBackend {
				db.Close()
				db, err = newStorage()
				if err != nil {
					t.Errorf("NewDiskStorage err %s", err)
				}
			}

			// Get
			for i := range objs {
				gotObj, err := db.Get(objs[i].Name)
				if err != nil {
					t.Errorf("db Put err %s", err)
				}
				t.Logf("got obj %+v", gotObj)
				assert.Equal(t, objs[i], gotObj)
			}
			// List
			listObjs := db.List()
			assert.Equal(t, len(objs), len(listObjs))
			// Delete
			err = db.Delete(objs[0].Name)
			if err != nil {
				t.Errorf("db Delete err %s", err)
			}

			// Reload data from disk.
			if test.useDiskBackend {
				db.Close()
				db, err = newStorage()
				if err != nil {
					t.Errorf("NewDiskStorage err %s", err)
				}
			}
			listObjs = db.List()
			assert.Equal(t, len(objs)-1, len(listObjs))
		})
	}
}
