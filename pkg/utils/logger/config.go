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

import "os"

const (
	envLogLevel     = "CELLO_CNI_LOGLEVEL"
	defaultLogLevel = "info"
	envLogLocation  = "CELLO_CNI_LOCATION"

	envReportCaller     = "CELLO_CNI_LOG_CALLER"
	defaultReportCaller = false
)

// Configuration stores the config of the logger.
type Configuration struct {
	LogLevel     string
	LogLocation  string
	ReportCaller bool
}

// LoadLogConfig returns the log configuration.
func LoadLogConfig() *Configuration {
	return &Configuration{
		LogLevel:     GetLogLevel(),
		LogLocation:  GetLogLocation(),
		ReportCaller: GetLogReportCaller(),
	}
}

// GetLogLocation get the log location from env.
func GetLogLocation() string {
	logLocation := os.Getenv(envLogLocation)
	return logLocation
}

// GetLogLevel get the log level from env.
func GetLogLevel() string {
	logLevel := os.Getenv(envLogLevel)
	if logLevel == "" {
		logLevel = defaultLogLevel
	}

	return logLevel
}

func GetLogReportCaller() bool {
	reportCaller := os.Getenv(envReportCaller)
	switch reportCaller {
	case "true":
		return true
	case "false":
		return false
	default:
		return defaultReportCaller
	}
}
