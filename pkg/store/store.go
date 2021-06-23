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

import "errors"

// ErrNotFound key not found in store.
var ErrNotFound = errors.New("not found")

// Interface offers a generic interface for data persistence operations.
type Interface interface {
	// Put save the value for the given key.
	Put(key string, value interface{}) error
	// Get retrieves the value for the given key.
	Get(key string) (interface{}, error)
	// List returns all values in storage.
	List() []interface{}
	// Delete deletes the value for the given key.
	Delete(key string) error
	// Close closes the storage.
	Close()
}

// Serializer transforms the given object into serialized format.
type Serializer func(interface{}) ([]byte, error)

// Deserializer transforms the given serialized data into the original object.
type Deserializer func([]byte) (interface{}, error)
