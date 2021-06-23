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
	"container/heap"
)

type queue []*poolItem

func (q *queue) Len() int {
	return len(*q)
}

func (q *queue) Less(i, j int) bool {
	origin := *q
	return origin[i].reserveBefore.Before(origin[j].reserveBefore)
}

func (q *queue) Swap(i, j int) {
	origin := *q
	origin[i], origin[j] = origin[j], origin[i]
}

func (q *queue) Push(x any) {
	item, ok := x.(*poolItem)
	if !ok {
		return
	}
	for _, in := range *q {
		if in.res.GetID() == item.res.GetID() {
			in.reserveBefore = item.reserveBefore
			return
		}
	}
	*q = append(*q, item)
}

func (q *queue) Pop() any {
	old := *q
	l := len(old)
	if l == 0 {
		return nil
	}
	item := old[l-1]
	*q = old[0 : l-1]
	return item
}

type priorityQueue struct {
	innerQueue queue
}

func (q *priorityQueue) PopPrefer(id string) *poolItem {
	if id == "" {
		return q.Pop()
	}
	size := q.Size()
	for i := 0; i < size; i++ {
		item := q.innerQueue[i]
		if item.res.GetID() == id {
			q.innerQueue[i] = q.innerQueue[size-1]
			q.innerQueue = q.innerQueue[0 : size-1]
			heap.Fix(&q.innerQueue, i)
			return item
		}
	}
	return nil
}

func (q *priorityQueue) Peek() *poolItem {
	if q.Size() == 0 {
		return nil
	}
	item := q.innerQueue[0]
	return item
}

func (q *priorityQueue) Pop() *poolItem {
	if q.Size() == 0 {
		return nil
	}
	item := heap.Pop(&q.innerQueue)
	return item.(*poolItem)
}

func (q *priorityQueue) Push(item *poolItem) {
	heap.Push(&q.innerQueue, item)
}

func (q *priorityQueue) Size() int {
	if q == nil {
		return 0
	}
	return len(q.innerQueue)
}

func (q *priorityQueue) Find(id string) *poolItem {
	for i := 0; i < q.Size(); i++ {
		if q.innerQueue[i].res.GetID() == id {
			return q.innerQueue[i]
		}
	}
	return nil
}

func (q *priorityQueue) Dump() map[string]*poolItem {
	ret := map[string]*poolItem{}
	for i := 0; i < q.Size(); i++ {
		item := q.innerQueue[i]
		ret[item.res.GetID()] = item
	}
	return ret
}

func newPriorityQueue() *priorityQueue {
	q := &priorityQueue{
		innerQueue: queue{},
	}
	heap.Init(&q.innerQueue)
	return q
}
