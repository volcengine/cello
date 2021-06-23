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
	"sync"

	"github.com/boltdb/bolt"
)

// DiskStorage is used to store data in disk.
type DiskStorage struct {
	db           *bolt.DB
	name         string
	cache        sync.Map
	serializer   Serializer
	deserializer Deserializer
}

func NewDiskStorage(name string, path string, serializer Serializer, deserializer Deserializer) (Interface, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	diskStorage := &DiskStorage{
		db:           db,
		name:         name,
		serializer:   serializer,
		deserializer: deserializer,
	}
	err = diskStorage.load()
	if err != nil {
		return nil, err
	}

	return diskStorage, nil
}

func (d *DiskStorage) Put(key string, value interface{}) error {
	data, err := d.serializer(value)
	if err != nil {
		return err
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(d.name))
		return b.Put([]byte(key), data)
	})
	if err != nil {
		return err
	}
	d.cache.Store(key, value)
	return nil
}

// load data from disk.
func (d *DiskStorage) load() error {
	if err := d.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(d.name))
		return err
	}); err != nil {
		return err
	}

	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(d.name))
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			obj, err := d.deserializer(v)
			if err != nil {
				return err
			}
			d.cache.Store(string(k), obj)
		}
		return nil
	})
	return err
}

func (d *DiskStorage) Get(key string) (interface{}, error) {
	value, ok := d.cache.Load(key)
	if !ok {
		return nil, ErrNotFound
	}
	return value, nil
}

// List values in disk storage.
func (d *DiskStorage) List() []interface{} {
	var values []interface{}
	d.cache.Range(func(_, v any) bool {
		values = append(values, v)
		return true
	})
	return values
}

func (d *DiskStorage) Delete(key string) error {
	if err := d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(d.name))
		return b.Delete([]byte(key))
	}); err != nil {
		return err
	}
	d.cache.Delete(key)
	return nil
}

func (d *DiskStorage) Close() {
	_ = d.db.Close()
}
