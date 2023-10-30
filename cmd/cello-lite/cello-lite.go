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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/volcengine/cello/pkg/utils/device"
	"github.com/volcengine/cello/pkg/violin"
)

var (
	helpFlag    *bool
	versionFlag *bool
	configFlag  *string
)

func main() {
	defer fmt.Println("agent has exited")
	parseFlags()
	if *helpFlag {
		fmt.Println(usage(flag.CommandLine.FlagUsages()))
		return
	}

	if *versionFlag {
		fmt.Println(version())
		return
	}
	conf, err := initConfig()
	if err != nil {
		fmt.Printf("Failed to init cello-lite config: %v\n", err)
		return
	}

	options := make([]violin.LiteAgentOption, 0, 10)
	options = append(options, violin.WithK8sQPS(*conf.KubeClientQPS))
	options = append(options, violin.WithK8sBurst(*conf.KubeClientBurst))
	options = append(options, violin.WithUserAgent(*conf.UserAgent))
	options = append(options, violin.WithAgentAPIAddress(*conf.APIAddress))
	if conf.EnableIPAM {
		if conf.Networks.DevicePrefix != nil {
			devList := make([]violin.NetDevConfig, 0)
			fmt.Println(viper.GetString(ARGDeviceNamePrefix))
			links, err := device.ListLinksWithPrefix(*conf.Networks.DevicePrefix)
			if err != nil {
				fmt.Printf("Failed to get devices with prefix: %v due to %v\n", *conf.Networks.DevicePrefix, err)
			}
			for _, dev := range links {
				devList = append(devList, violin.NetDevConfig{
					DeviceName: dev.Attrs().Name,
					IpamMode:   "auto-detect",
				})
			}
			conf.Networks.Devices = devList
		}
		options = append(options, violin.WithIPManager(conf.Networks))
	}

	agent, err := violin.NewDaemonWithOptions(context.Background(), viper.GetString(ARGNodeName), options...)
	if err != nil {
		fmt.Printf("failed to initialize agent : %v\n", err)
		return
	}
	stopCh := make(chan os.Signal, 2)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	agentStarted := make(chan struct{})
	go func() {
		err = agent.Start(agentStarted)
		if err != nil {
			return
		}
	}()

	<-agentStarted
	go healthCheck(viper.GetString(ARGHealthCheckPort))

	<-stopCh
	agent.Stop()
}

func parseFlags() {
	flag.String(ARGNodeName, "n", "k8s node name")
	flag.Float64(ARGKubeClientQPS, violin.DefaultKubeClientQPS, "QPS for K8S APIServer")
	flag.Int(ARGKubeClientBurst, violin.DefaultKubeClientBurst, "Burst for K8S APIServer")
	flag.StringP(ARGUserAgent, "u", violin.DefaultUserAgent, "UserAgent of requests for K8S APIServer")
	flag.StringP(ARGApiAddress, "a", violin.DefaultRPCAddress, "agent RPC endpoint address")
	flag.String(ARGDeviceNamePrefix, "", "input the prefix of netdev that managed by IPAM")
	flag.String(ARGIpamStore, violin.DefaultIpamStoreDir, "Directory for IPAM records")
	flag.Bool(ARGEnableIPAM, true, "weather to use integrated IPAM")
	flag.String(ARGHealthCheckPort, "0.0.0.0:11414", "http port for health check")
	configFlag = flag.StringP(ARGConfig, "c", violin.DefaultConfigDir, "<path/to/config>")
	helpFlag = flag.BoolP(ARGHelp, "h", false, "help for cello-lite-agent")
	versionFlag = flag.BoolP(ARGVersion, "V", false, "show agent version information")
	flag.CommandLine.SetNormalizeFunc(wordSepNormalizeFunc)
	flag.Parse()
}

func initConfig() (*violin.Config, error) {
	viper.SetDefault(ARGConfig, violin.DefaultConfigDir)
	viper.SetDefault(ARGKubeClientQPS, violin.DefaultKubeClientQPS)
	viper.SetDefault(ARGKubeClientBurst, violin.DefaultKubeClientBurst)
	viper.SetDefault(ARGUserAgent, violin.DefaultUserAgent)
	viper.SetDefault(ARGApiAddress, violin.DefaultRPCAddress)
	viper.SetDefault(ARGNodeName, os.Getenv(ENVNodeName))
	viper.SetDefault(ARGIpamStore, violin.DefaultIpamStoreDir)

	viper.AddConfigPath(*configFlag)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("can't read configure file due to: %w", err)
	}

	err = viper.BindPFlags(flag.CommandLine)
	if err != nil {
		return nil, err
	}
	conf := &violin.Config{}

	err = viper.Unmarshal(conf)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal config file")
	}
	return conf, nil
}

func wordSepNormalizeFunc(f *flag.FlagSet, name string) flag.NormalizedName {
	from := []string{"-", "_"}
	to := "."
	for _, sep := range from {
		name = strings.Replace(name, sep, to, -1)
	}
	return flag.NormalizedName(name)
}

func usage(flagUsages string) string {
	return fmt.Sprintf(`
Cello-lite-agent, per-host daemon for Cello CNI.
Usage:
cello-lite-agent [options]
Options:
%s`, flagUsages)
}

func version() string {
	return "cello-lite" + violin.Version
}

func healthCheck(addr string) {
	http.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "ok")
	})
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Println("healthz service stopped due to" + err.Error())
	}
}
