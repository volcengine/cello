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

package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

func Execute() {
	if err := MigrateLocalPodDB(); err != nil {
		log.Fatalf("Convert pod format in persistence db before build daemon failed, %v", err)
	}

	d, err := NewDaemon()
	if err != nil {
		log.Fatalf("Create cello daemon failed, %v", err)
	}

	stopCh := make(chan struct{})
	go signalHandler(stopCh)

	err = d.start(stopCh)
	if err != nil {
		log.Fatalf("Run Daemon failed, %v", err)
	}
}

func signalHandler(stopCh chan struct{}) {
	sig := make(chan os.Signal, 1)
	var closeOnce sync.Once
	signal.Notify(sig,
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGABRT,
		syscall.SIGUSR1, syscall.SIGUSR2)

	for s := range sig {
		log.Infof(fmt.Sprintf("Cello-agent received user signal %d", s))
		switch s {
		case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM:
			log.Infof(fmt.Sprintf("cello-agent received user signal %d, graceful exit now...", s))
			closeOnce.Do(func() {
				close(stopCh)
				time.Sleep(1 * time.Second)
			})
		case syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGQUIT, syscall.SIGABRT:
			log.Infof(fmt.Sprintf("Cello-agent received user signal %d, graceful exit now...", s))
			log.Infof(string(debug.Stack()))
			closeOnce.Do(func() {
				close(stopCh)
				time.Sleep(1 * time.Second)
			})
		default:
			log.Warnf(fmt.Sprintf("Cello-agent receive unknown os term signal %v. ignore...", s))
		}
	}

}

func init() {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
}
