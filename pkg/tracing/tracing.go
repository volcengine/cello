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

package tracing

import (
	"errors"
	"sync"
)

var (
	defaultTracer Tracer
)

// PodEventRecorder records event on pod.
type PodEventRecorder func(podName, podNamespace, eventType, reason, message string) error

// NodeEventRecorder records event on node.
type NodeEventRecorder func(eventType, reason, message string)

// Tracer manages tracing handlers registered from the system.
type Tracer struct {
	mtx sync.Mutex

	podEvent  PodEventRecorder
	nodeEvent NodeEventRecorder
}

// RegisterEventRecorder registers pod & node event recorder to a tracer.
func (t *Tracer) RegisterEventRecorder(node NodeEventRecorder, pod PodEventRecorder) {
	t.nodeEvent = node
	t.podEvent = pod
}

// RecordPodEvent records pod event via PodEventRecorder.
func (t *Tracer) RecordPodEvent(podName, podNamespace, eventType, reason, message string) error {
	if t.podEvent == nil {
		return errors.New("no pod event recorder registered")
	}

	return t.podEvent(podName, podNamespace, eventType, reason, message)
}

// RecordNodeEvent records node event via PodEventRecorder.
func (t *Tracer) RecordNodeEvent(eventType, reason, message string) error {
	if t.nodeEvent == nil {
		return errors.New("no node event recorder registered")
	}

	t.nodeEvent(eventType, reason, message)
	return nil
}

// RegisterEventRecorder registers pod & node event recorder to a tracer.
func RegisterEventRecorder(node NodeEventRecorder, pod PodEventRecorder) {
	defaultTracer.RegisterEventRecorder(node, pod)
}

// RecordPodEvent records pod event via PodEventRecorder.
func RecordPodEvent(podName, podNamespace, eventType, reason, message string) error {
	return defaultTracer.RecordPodEvent(podName, podNamespace, eventType, reason, message)
}

// RecordNodeEvent records node event via PodEventRecorder.
func RecordNodeEvent(eventType, reason, message string) error {
	return defaultTracer.RecordNodeEvent(eventType, reason, message)
}

// NewTracer creates a new tracer.
func NewTracer() *Tracer {
	return &Tracer{
		mtx: sync.Mutex{},
	}
}

func DefaultGlobalTracer() *Tracer {
	return &defaultTracer
}
