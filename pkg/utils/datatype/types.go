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

package datatype

// String returns a pointer to the string value passed in.
func String(v string) *string {
	return &v
}

// StringValue returns the value of the string pointer passed in or
// "" if the pointer is nil.
func StringValue(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// Float64 returns a pointer to the float64 value passed in.
func Float64(v float64) *float64 {
	return &v
}

// Float64Value returns the value of the float64 pointer passed in or
// 0 if the pointer is nil.
func Float64Value(f *float64) float64 {
	if f != nil {
		return *f
	}
	return 0
}

// Int returns a pointer to the int value passed in.
func Int(v int) *int {
	return &v
}

// IntValue returns the value of the int pointer passed in or
// 0 if the pointer is nil.
func IntValue(v *int) int {
	if v != nil {
		return *v
	}
	return 0
}

// Uint16 returns a pointer to the uint16 value passed in.
func Uint16(v uint16) *uint16 {
	return &v
}

// Uint16Value returns the value of the uint16 pointer passed in or
// 0 if the pointer is nil.
func Uint16Value(p *uint16) uint16 {
	if p == nil {
		return 0
	}
	return *p
}

// Uint32 returns a pointer to the uint32 value passed in.
func Uint32(v uint32) *uint32 {
	return &v
}

// Uint32Value returns the value of the uint32 pointer passed in or
// 0 if the pointer is nil.
func Uint32Value(v *uint32) uint32 {
	if v != nil {
		return *v
	}
	return 0
}

// Bool returns a pointer to the bool value passed in.
func Bool(v bool) *bool {
	return &v
}

// BoolValue returns the value of the bool pointer passed in or
// false if the pointer is nil.
func BoolValue(b *bool) bool {
	if b != nil {
		return *b
	}
	return false
}
