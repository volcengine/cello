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

package logger

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/natefinch/lumberjack.v2"
)

func TestEnvLogLocation(t *testing.T) {
	location := "./log_test.log"
	_ = os.Setenv(envLogLocation, location)
	defer os.Unsetenv(envLogLocation)

	assert.Equal(t, location, GetLogLocation())
}

func TestLogLevelReturnsOverridenLevel(t *testing.T) {
	_ = os.Setenv(envLogLevel, "DEBUG")
	defer os.Unsetenv(envLogLevel)

	expectedLevel := logrus.DebugLevel
	inputLogLevel := GetLogLevel()
	assert.Equal(t, expectedLevel, getLogrusLevel(inputLogLevel))
}

func TestLogLevelReturnsDefaultLevelWhenEnvNotSet(t *testing.T) {
	expectedLogLevel := logrus.InfoLevel
	inputLogLevel := GetLogLevel()
	assert.Equal(t, expectedLogLevel, getLogrusLevel(inputLogLevel))
}

func TestLogLevelReturnsDefaultLevelWhenEnvSetToInvalidValue(t *testing.T) {
	_ = os.Setenv(envLogLevel, "EVERYTHING")
	defer os.Unsetenv(envLogLevel)

	var expectedLogLevel logrus.Level
	inputLogLevel := GetLogLevel()
	expectedLogLevel = logrus.InfoLevel
	assert.Equal(t, expectedLogLevel, getLogrusLevel(inputLogLevel))
}

func TestGetLogrusLocationEmpty(t *testing.T) {
	logLocation := ""
	assert.Equal(t, os.Stderr, getLogrusLocation(logLocation))
}

func TestGetLogrusLocationStdout(t *testing.T) {
	expectedWriter := os.Stdout
	logLocation := "stdout"
	assert.Equal(t, expectedWriter, getLogrusLocation(logLocation))
}

func TestGetLogrusLocation(t *testing.T) {
	logLocation := "./log_test.log"
	if !isFileExist(logLocation) {
		_, err := os.Create(logLocation)
		if err != nil {
			t.Error("create file error")
		}
	}
	defer os.Remove(logLocation)
	expectedLumberJackLogger := &lumberjack.Logger{
		Filename:   "./log_test.log",
		MaxSize:    256,
		MaxBackups: 2,
		MaxAge:     7,
		Compress:   true,
	}
	assert.Equal(t, expectedLumberJackLogger, getLogrusLocation(logLocation))
}

func TestLoggerStdout(_ *testing.T) {
	config := &Configuration{
		LogLevel:     "Info",
		LogLocation:  "stdout",
		ReportCaller: true,
	}

	log := New(config)
	log.Debug("this is a test for logger[debug]")
	log.Info("this is a test for logger[info]")
	log.Warn("this is a test for logger[warn]")
	log.Error("this is a test for logger[error]")
}

func TestLoggerFile(t *testing.T) {
	logfile := "./log_test.log"
	if !isFileExist(logfile) {
		_, err := os.Create(logfile)
		if err != nil {
			t.Error("create file error")
		}
	}

	config := &Configuration{
		LogLevel:    "Debug",
		LogLocation: logfile,
	}

	log := New(config)
	log.Debug("this is a test for logger[debug]")
	log.Info("this is a test for logger[info]")
	log.Warn("this is a test for logger[warn]")
	log.Error("this is a test for logger[error]")
}

func isFileExist(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil {
		return os.IsExist(err)
	}
	return true
}

func TestLoggerWithFields(_ *testing.T) {
	config := &Configuration{
		LogLevel:    "Info",
		LogLocation: "stdout",
	}

	log := New(config)

	fields := Fields{
		"key1": "val1",
		"key2": "val2",
	}
	log.DebugWithFields(fields, "this is a test for logger[debug]")
	log.InfoWithFields(fields, "this is a test for logger[info]")
	log.WarnWithFields(fields, "this is a test for logger[warn]")
	log.ErrorWithFields(fields, "this is a test for logger[error]")
}

func TestLoggerWithFields2(_ *testing.T) {
	config := &Configuration{
		LogLevel:     "Info",
		LogLocation:  "stdout",
		ReportCaller: true,
	}

	log := New(config)

	fields := Fields{
		"key1": "val1",
		"key2": "val2",
	}
	log = log.WithFields(fields)

	log.Debug("this is a test for logger[debug]")
	log.Info("this is a test for logger[info]")
	log.Warn("this is a test for logger[warn]")
	log.Error("this is a test for logger[error]")

	fields2 := Fields{
		"key3": "val3",
	}
	log = log.WithFields(fields2)
	log.Info("this is a test for logger[info]")
	log.Warn("this is a test for logger[warn]")
	log.Error("this is a test for logger[error]")
}
