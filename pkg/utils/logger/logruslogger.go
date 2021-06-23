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
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type structuredLogger struct {
	logrusLogger *logrus.Entry
}

var levelMap = map[string]logrus.Level{
	"trace": logrus.TraceLevel,
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
	"warn":  logrus.WarnLevel,
	"error": logrus.ErrorLevel,
	"fatal": logrus.FatalLevel,
	"panic": logrus.PanicLevel,
}

func (logf *structuredLogger) Debugf(format string, args ...interface{}) {
	logf.logrusLogger.Debugf(format, args...)
}

func (logf *structuredLogger) Debug(args ...interface{}) {
	logf.logrusLogger.Debug(args...)
}

func (logf *structuredLogger) DebugWithFields(fields Fields, args ...interface{}) {
	logf.logrusLogger.WithFields(logrus.Fields(fields)).Debug(args...)
}

func (logf *structuredLogger) Infof(format string, args ...interface{}) {
	logf.logrusLogger.Infof(format, args...)
}

func (logf *structuredLogger) Info(args ...interface{}) {
	logf.logrusLogger.Info(args...)
}

func (logf *structuredLogger) InfoWithFields(fields Fields, args ...interface{}) {
	logf.logrusLogger.WithFields(logrus.Fields(fields)).Info(args...)
}

func (logf *structuredLogger) Warnf(format string, args ...interface{}) {
	logf.logrusLogger.Warnf(format, args...)
}

func (logf *structuredLogger) Warn(args ...interface{}) {
	logf.logrusLogger.Warn(args...)
}

func (logf *structuredLogger) WarnWithFields(fields Fields, args ...interface{}) {
	logf.logrusLogger.WithFields(logrus.Fields(fields)).Warn(args...)
}

func (logf *structuredLogger) Errorf(format string, args ...interface{}) {
	logf.logrusLogger.Errorf(format, args...)
}

func (logf *structuredLogger) Error(args ...interface{}) {
	logf.logrusLogger.Error(args...)
}

func (logf *structuredLogger) ErrorWithFields(fields Fields, args ...interface{}) {
	logf.logrusLogger.WithFields(logrus.Fields(fields)).Error(args...)
}

func (logf *structuredLogger) Fatalf(format string, args ...interface{}) {
	logf.logrusLogger.Fatalf(format, args...)
}

func (logf *structuredLogger) Panicf(format string, args ...interface{}) {
	logf.logrusLogger.Panicf(format, args...)
}

func (logf *structuredLogger) WithFields(fields Fields) Logger {
	entry := logf.logrusLogger.WithFields(logrus.Fields(fields))
	return &structuredLogger{entry}
}

func (logf *structuredLogger) SetLogLevel(level string) {
	logf.logrusLogger.Logger.SetLevel(getLogrusLevel(level))
}

func isValidFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !s.IsDir()
}

func getLogrusLevel(logLevel string) logrus.Level {
	lglv := strings.ToLower(logLevel)
	if level, ok := levelMap[lglv]; ok {
		return level
	}
	return logrus.InfoLevel
}

// getLogrusLocation return a Writer according to the configuration.
func getLogrusLocation(logLocation string) io.Writer {
	if strings.ToLower(logLocation) == "stdout" {
		return os.Stdout
	}

	if !isValidFile(logLocation) {
		return os.Stderr
	}
	return &lumberjack.Logger{
		Filename:   logLocation,
		MaxSize:    256,
		MaxAge:     7,
		MaxBackups: 2,
		Compress:   true,
	}
}

// newLogrusLogger create a new logrus logger instance according to the config.
func (logConfig *Configuration) newLogrusLogger() *structuredLogger {
	logLevel := getLogrusLevel(logConfig.LogLevel)
	logLocation := getLogrusLocation(logConfig.LogLocation)
	logger := logrus.New()
	logger.SetLevel(logLevel)
	logger.SetOutput(logLocation)
	if logConfig.ReportCaller {
		hook := NewHook()
		hook.Field = "line"
		logger.AddHook(hook)
	}

	return &structuredLogger{logrusLogger: logrus.NewEntry(logger)}
}

type Hook struct {
	Field     string
	Skip      int
	levels    []logrus.Level
	Formatter func(file, function string, line int) string
}

func (hook *Hook) Levels() []logrus.Level {
	return hook.levels
}

func (hook *Hook) Fire(entry *logrus.Entry) error {
	entry.Data[hook.Field] = hook.Formatter(findCaller(hook.Skip))
	return nil
}

func NewHook(levels ...logrus.Level) *Hook {
	hook := Hook{
		Field:  "source",
		Skip:   5,
		levels: levels,
		Formatter: func(file, function string, line int) string {
			return fmt.Sprintf("%s:%d", file, line)
		},
	}
	if len(hook.levels) == 0 {
		hook.levels = logrus.AllLevels
	}

	return &hook
}

func findCaller(skip int) (string, string, int) {
	var (
		pc uintptr
		f  string
		fc string
		l  int
	)
	for i := 0; i < 10; i++ {
		pc, f, l = getCaller(skip + i)
		if !strings.HasPrefix(f, "logrus") && !strings.HasPrefix(f, "logger") {
			break
		}
	}
	if pc != 0 {
		frames := runtime.CallersFrames([]uintptr{pc})
		frame, _ := frames.Next()
		fc = frame.Function
	}

	return f, fc, l
}

func getCaller(skip int) (uintptr, string, int) {
	pc, f, l, ok := runtime.Caller(skip)
	if !ok {
		return 0, "", 0
	}

	n := 0
	for i := len(f) - 1; i > 0; i-- {
		if f[i] == '/' {
			n++
			if n >= 2 {
				f = f[i+1:]
				break
			}
		}
	}

	return pc, f, l
}
