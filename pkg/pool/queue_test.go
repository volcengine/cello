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

package pool

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/volcengine/cello/types"
)

const (
	secondBefore = 100
)

func TestNew(t *testing.T) {
	q := newPriorityQueue()
	assert.Zero(t, q.Size())
}

func randPoolItem(id string) *poolItem {
	rand.Seed(time.Now().Unix())
	t := rand.Intn(secondBefore)
	return &poolItem{
		reserveBefore: time.Now().Add(-time.Duration(t) * time.Second),
		res:           &types.MockNetResource{ID: id},
	}
}

func TestPushAndPop(t *testing.T) {
	q := newPriorityQueue()
	for i := 0; i < 50; i++ {
		q.Push(randPoolItem(fmt.Sprintf("ID-%d", i)))
	}
	assert.Equal(t, 50, q.Size())

	base := time.Time{}
	cnt := 0
	for {
		item := q.Pop()
		if item == nil {
			break
		}
		cnt++
		if base.Before(item.reserveBefore) {
			base = item.reserveBefore
		} else {
			t.Fatalf("priority queue inner error")
		}
	}
	assert.Equal(t, 50, cnt)
}

func TestPushExistItem(t *testing.T) {
	q := newPriorityQueue()
	for i := 0; i < 3; i++ {
		q.Push(randPoolItem(fmt.Sprintf("ID-%d", i)))
	}

	sameOne := randPoolItem("ID-1")
	q.Push(sameOne)
	assert.Equal(t, 3, q.Size())
	assert.Equal(t, q.Find("ID-1").reserveBefore, sameOne.reserveBefore)
}

func TestPeek(t *testing.T) {
	q := newPriorityQueue()
	for i := 0; i < 50; i++ {
		q.Push(randPoolItem(fmt.Sprintf("ID-%d", i)))
	}
	assert.Equal(t, 50, q.Size())

	for {
		peek := q.Peek()
		pop := q.Pop()
		if peek == nil && pop == nil {
			break
		}
		assert.Equal(t, peek.res.GetID(), pop.res.GetID())
	}
}

func TestFind(t *testing.T) {
	q := newPriorityQueue()
	for i := 0; i < 50; i++ {
		q.Push(randPoolItem(fmt.Sprintf("ID-%d", i)))
	}
	assert.Nil(t, q.Find("ID-100"))
	item := q.Find("ID-20")
	assert.Equal(t, "ID-20", item.res.GetID())
	assert.Equal(t, 50, q.Size())
}

func TestPopPrefer(t *testing.T) {
	q := newPriorityQueue()
	for i := 0; i < 50; i++ {
		q.Push(randPoolItem(fmt.Sprintf("ID-%d", i)))
	}
	assert.Equal(t, 50, q.Size())
	assert.Nil(t, q.PopPrefer("ID-100"))
	assert.Equal(t, 50, q.Size())
	item20 := q.PopPrefer("ID-20")
	assert.Equal(t, "ID-20", item20.res.GetID())
	item40 := q.PopPrefer("ID-40")
	assert.Equal(t, "ID-40", item40.res.GetID())
	itemAny := q.PopPrefer("")
	assert.NotNil(t, itemAny)
	assert.Equal(t, 47, q.Size())

	base := time.Time{}
	cnt := 0
	for {
		item := q.Pop()
		if item == nil {
			break
		}
		if cnt == 0 && itemAny.reserveBefore.After(item.reserveBefore) {
			t.Fatalf("error")
		}
		cnt++
		if base.Before(item.reserveBefore) {
			base = item.reserveBefore
		} else {
			t.Fatalf("priority queue inner error")
		}
	}
	assert.Equal(t, 47, cnt)
}
