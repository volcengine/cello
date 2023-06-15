package runtime

import (
	"github.com/volcengine/cello/pkg/utils/logger"
	"runtime"
)

func logPanic(r interface{}, log logger.Logger) {
	// Same as stdlib http server code. Manually allocate stack trace buffer size
	// to prevent excessively large logs
	const size = 64 << 10
	stacktrace := make([]byte, size)
	stacktrace = stacktrace[:runtime.Stack(stacktrace, false)]
	if _, ok := r.(string); ok {
		log.Errorf("Observed a panic: %s\n%s\n", r, stacktrace)
	} else {
		log.Errorf("Observed a panic: %#v (%v)\n%s", r, r, stacktrace)
	}
}

func HandleCrash(log logger.Logger) {
	if r := recover(); r != nil {
		logPanic(r, log)
	}
}
