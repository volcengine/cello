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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/pkg/utils/logger"
	"github.com/volcengine/cello/pkg/utils/sysctl"
	"github.com/volcengine/cello/types"
)

// cilium Launcher pre_start_check and start cilium while work with cello

const (
	ciliumConfigPath = "/etc/cilium/cilium-config"
	celloConfigPath  = "/etc/cilium/cello-config"
)

type KV map[string]interface{}

func (kv KV) ToArgs() []string {
	var args []string
	for k, v := range kv {
		args = append(args, fmt.Sprintf("--%v=%v", k, v))
	}
	return args
}

func AppendKV(kv1, kv2 KV) KV {
	kv := KV{}
	for k, v := range kv1 {
		kv[k] = v
	}
	for k, v := range kv2 {
		kv[k] = v
	}
	return kv
}

var (
	ciliumBaseArgs = KV{
		"agent-health-port":               "9099",
		"bpf-map-dynamic-size-ratio":      "0.0025",
		"disable-envoy-version-check":     "true",
		"direct-routing-device":           "eth0",
		"datapath-mode":                   "ipvlan",
		"debug":                           "false",
		"enable-endpoint-health-checking": "false",
		"enable-host-legacy-routing":      "true",
		"enable-local-node-route":         "false",
		"ipam":                            "cluster-pool",
		"ipvlan-master-device":            "eth0",
		"kube-proxy-replacement":          "strict",
		"node-port-mode":                  "snat",
		"tunnel":                          "disabled",
		"enable-policy":                   "never",
		"enable-bandwidth-manager":        "true",
	}

	ciliumIPv4Args = KV{
		"enable-ipv4":            "true",
		"enable-ipv4-masquerade": "false",
		"ipv4-range":             "169.254.0.0/16",
	}

	ciliumIPv6Args = KV{
		"enable-ipv6":            "true",
		"enable-ipv6-masquerade": "false",
		"ipv6-range":             "fe80:2400:3200:baba::/30",
	}
)

var (
	log = logger.GetLogger().WithFields(logger.Fields{"subsys": "cilium-launcher"})
)

type ciliumLauncherConfig struct {
	PreHealthPort uint16
}

func NewCiliumLauncherConfig() *ciliumLauncherConfig {
	return &ciliumLauncherConfig{PreHealthPort: config.DefaultDebugPort}
}

func (c *ciliumLauncherConfig) AddFlags(fs *pflag.FlagSet) {
	fs.Uint16Var(&c.PreHealthPort, "pre-health-port", c.PreHealthPort, "Pre health check before launcher cilium")
}

func main() {
	c := NewCiliumLauncherConfig()
	c.AddFlags(pflag.CommandLine)
	pflag.Parse()

	// first, check if cello is running
	for {
		response, err := http.Get(fmt.Sprintf("http://localhost:%d/healthz", c.PreHealthPort))
		if err != nil || response.StatusCode != http.StatusOK {
			time.Sleep(1 * time.Second)
			log.Warnf("Cello agent not ready, err: %v", err)
			continue
		}
		bodyText, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			log.Warnf("Cello agent not ready, err: %v", err)
			continue
		}
		if string(bodyText) == "ok" {
			break
		}
	}
	log.Infof("Cello ready, launch cilium...")

	// disable rp_filter
	err := sysctl.Disable("net.ipv4.conf.eth0.rp_filter")
	if err != nil {
		log.Fatalf("Disable rp_filter for eth0 failed, %v", err)
	}

	// check apiServer info
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		log.Fatalf("Cilium need k8s datastore, but can not found [KUBERNETES_SERVICE_HOST] env, exit.")
	}

	// launch cilium
	var ciliumCmd *exec.Cmd
	celloConfigFile, err := os.Open(celloConfigPath)
	if err != nil {
		log.Fatalf("Get cello config failed, %v", err)
	}
	defer celloConfigFile.Close()

	decoder := json.NewDecoder(celloConfigFile)
	var celloConfig config.Config
	err = decoder.Decode(&celloConfig)
	if err != nil {
		log.Fatalf("Decode cello config failed, %v", err)
	}
	ipFamily := types.IPFamily(datatype.StringValue(celloConfig.IPFamily))
	ciliumArgs := ciliumBaseArgs
	if ipFamily.EnableIPv4() {
		ciliumArgs = AppendKV(ciliumArgs, ciliumIPv4Args)
	}
	if ipFamily.EnableIPv6() {
		ciliumArgs = AppendKV(ciliumArgs, ciliumIPv6Args)
	} else {
		ciliumArgs = AppendKV(ciliumArgs, KV{"enable-ipv6": "false"})
	}

	if mode := datatype.StringValue(celloConfig.NetworkMode); mode == config.NetworkModeENIExclusive {
		ciliumArgs = AppendKV(ciliumArgs, KV{"eni-mode-exclusive": "true"})
	}

	err = filepath.Walk(ciliumConfigPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			info, err = os.Stat(realPath)
			if err != nil {
				return err
			}
		}
		if !info.IsDir() {
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			key := filepath.Base(path)
			ciliumArgs[key] = string(value)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Read custom cilium config failed, %v", err)
	}

	policyState := fmt.Sprintf("%v", ciliumArgs["enable-policy"])
	ciliumExitChan := make(chan struct{})
	var lock sync.Mutex

	go func() {
		log.Infof("Run cilium-agent with args: %v", ciliumArgs.ToArgs())
		lock.Lock()
		ciliumCmd = exec.Command("cilium-agent", ciliumArgs.ToArgs()...)
		ciliumCmd.Stdin = os.Stdin
		ciliumCmd.Stdout = os.Stdout
		ciliumCmd.Stderr = os.Stderr
		err = ciliumCmd.Start()
		if err != nil {
			log.Fatalf("Launch cilium failed, %v", err)
		}
		lock.Unlock()

		log.Infof("Cilium launched")
		err = ciliumCmd.Wait()
		if err != nil {
			log.Errorf("Wait failed: %v", err)
		}
		close(ciliumExitChan)
	}()

	policyCfgPath := path.Join(ciliumConfigPath, "enable-policy")
	policyEvent := make(chan *ValueEvent, 1)
	watchPath(policyCfgPath, &policyState, policyEvent, 10*time.Second)

	// press signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	exitCilium := func() {
		log.Infof("cilium exiting")
		err = ciliumCmd.Process.Signal(syscall.SIGINT)
		if err != nil {
			log.Infof("INT cilium failed: %v", err)
		}

		t := time.NewTimer(30 * time.Second)
		select {
		case <-ciliumExitChan:
			log.Infof("cilium exited, code: %d", ciliumCmd.ProcessState.ExitCode())
			os.Exit(ciliumCmd.ProcessState.ExitCode())
		case <-t.C:
			t.Stop()
			log.Infof("wait cilium finish timeout")
			os.Exit(1)
		}
	}

	for {
		select {
		case sig := <-sigCh:
			log.Infof("%d signal: %s", os.Getpid(), sig.String())
			lock.Lock()
			if ciliumCmd != nil {
				exitCilium()
			}
		case pe := <-policyEvent:
			lock.Lock()
			if ciliumCmd != nil {
				if pe.err != nil {
					log.Errorf("watch policy state failed, %v", pe.err)
					exitCilium()
				}
				if pe.value != "default" && pe.value != "always" && pe.value != "never" {
					log.Errorf("Invalid value '%s' for enable-policy", pe.value)
				} else {
					if err = setPolicyState(pe.value); err != nil {
						log.Errorf("Switch enable-policy to %s failed, %v", pe.value, err)
						exitCilium()
					}
				}
			}
			lock.Unlock()
		case <-ciliumExitChan:
			log.Infof("cilium unexpect exited, code: %d", ciliumCmd.ProcessState.ExitCode())
			os.Exit(ciliumCmd.ProcessState.ExitCode())
		}
	}
}

func setPolicyState(value string) error {
	log.Infof("Switch enable-policy to %s", value)
	cfg := fmt.Sprintf("PolicyEnforcement=%s", value)
	policyCmd := exec.Command("cilium", "config", cfg)
	output, err := policyCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmd execute failed, output: %v, err: %v", output, err)
	}
	log.Infof("Switch enable-policy to %s success", value)
	return nil
}

type ValueEvent struct {
	value string
	err   error
}

func watchPath(path string, oldValue *string, valueEvent chan<- *ValueEvent, period time.Duration) {
	go wait.Forever(func() {
		value, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			event := &ValueEvent{
				value: "",
				err:   fmt.Errorf("read %s failed, %v", path, err),
			}
			valueEvent <- event
			return
		}
		newValue := string(value)
		if newValue != *oldValue {
			*oldValue = newValue
			valueEvent <- &ValueEvent{
				value: newValue,
			}
		}
	}, period)
}
