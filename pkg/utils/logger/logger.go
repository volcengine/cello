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

// Package logger is the CNI logger interface, using logrus
package logger

// log is a global var so that log function can be directly accessed.
var log Logger

// Fields Used when we want to call WithFields for structured logging.
type Fields map[string]interface{}

type Logger interface {
	Debugf(format string, args ...interface{})

	Debug(args ...interface{})

	DebugWithFields(fields Fields, args ...interface{})

	Infof(format string, args ...interface{})

	Info(args ...interface{})

	InfoWithFields(fields Fields, args ...interface{})

	Warnf(format string, args ...interface{})

	Warn(args ...interface{})

	WarnWithFields(fields Fields, args ...interface{})

	Errorf(format string, args ...interface{})

	Error(args ...interface{})

	ErrorWithFields(fields Fields, args ...interface{})

	Fatalf(format string, args ...interface{})

	Panicf(format string, args ...interface{})

	WithFields(fields Fields) Logger

	SetLogLevel(level string)
}

// GetLogger return the default instance.
func GetLogger() Logger {
	if log == nil {
		logConfig := LoadLogConfig()
		log = New(logConfig)
	}

	return log
}

// New return new initializes logger.
func New(config *Configuration) Logger {
	return config.newLogrusLogger()
}
