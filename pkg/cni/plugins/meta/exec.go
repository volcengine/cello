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

package meta

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/metrics"
)

type MetaExec struct {
	exec invoke.Exec
}

var _ invoke.Exec = &MetaExec{}

func NewMetaExec() *MetaExec {
	return &MetaExec{
		exec: &invoke.DefaultExec{
			RawExec:       &invoke.RawExec{Stderr: os.Stderr},
			PluginDecoder: version.PluginDecoder{},
		},
	}
}

func (e *MetaExec) ExecPlugin(ctx context.Context, pluginPath string, stdinData []byte, environ []string) ([]byte, error) {

	if ExecMetaShimFactorys.IsExistPlugin(pluginPath) {
		// if plugin support inside plugin, execute it
		cmd, cmdArgs, err := getCmdArgsFromEnvString(environ)
		if err != nil {
			return nil, err
		}
		cmdArgs.StdinData = stdinData
		switch cmd {
		case "ADD":
			return ExecMetaShimFactorys.ExecCMDAdd(pluginPath, cmdArgs)
		case "DEL":
			return ExecMetaShimFactorys.ExecCMDDel(pluginPath, cmdArgs)
		case "CHECK":
			return nil, nil
		case "VERSION":
			return nil, nil
		default:
			return nil, fmt.Errorf("unknown cmd %s", cmd)
		}
	}

	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		log.Log.InfoS("ExecPlugin time cost Millisecond", "cost", fmt.Sprintf("%f", duration), "pluginPath", pluginPath)
	}()
	return e.exec.ExecPlugin(ctx, pluginPath, stdinData, environ)
}

// FindInPath
// plugin is network type
func (e *MetaExec) FindInPath(plugin string, paths []string) (string, error) {
	// just use origin type name as plugin path
	if ExecMetaShimFactorys.IsExistPlugin(plugin) {
		return plugin, nil
	}
	return e.exec.FindInPath(plugin, paths)
}

func (e *MetaExec) Decode(jsonBytes []byte) (version.PluginInfo, error) {
	return e.exec.Decode(jsonBytes)
}

type reqForCmdEntry map[string]bool

func getCmdArgsFromEnvString(environ []string) (string, *skel.CmdArgs, *types.Error) {
	var cmd, contID, netns, ifName, args, path string

	envMap := map[string]string{}
	for _, kv := range environ {
		// find the first "=" in environment, if not, just keep it
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		envMap[kv[:eq]] = kv[eq+1:]
	}

	vars := []struct {
		name      string
		val       *string
		reqForCmd reqForCmdEntry
	}{
		{
			"CNI_COMMAND",
			&cmd,
			reqForCmdEntry{
				"ADD":   true,
				"CHECK": true,
				"DEL":   true,
			},
		},
		{
			"CNI_CONTAINERID",
			&contID,
			reqForCmdEntry{
				"ADD":   true,
				"CHECK": true,
				"DEL":   true,
			},
		},
		{
			"CNI_NETNS",
			&netns,
			reqForCmdEntry{
				"ADD":   true,
				"CHECK": true,
				"DEL":   false,
			},
		},
		{
			"CNI_IFNAME",
			&ifName,
			reqForCmdEntry{
				"ADD":   true,
				"CHECK": true,
				"DEL":   true,
			},
		},
		{
			"CNI_ARGS",
			&args,
			reqForCmdEntry{
				"ADD":   false,
				"CHECK": false,
				"DEL":   false,
			},
		},
		{
			"CNI_PATH",
			&path,
			reqForCmdEntry{
				"ADD":   true,
				"CHECK": true,
				"DEL":   true,
			},
		},
	}

	argsMissing := make([]string, 0)
	for _, v := range vars {
		*v.val = envMap[v.name]
		if *v.val == "" {
			if v.reqForCmd[cmd] || v.name == "CNI_COMMAND" {
				argsMissing = append(argsMissing, v.name)
			}
		}
	}

	if len(argsMissing) > 0 {
		joined := strings.Join(argsMissing, ",")
		return "", nil, types.NewError(types.ErrInvalidEnvironmentVariables, fmt.Sprintf("required env variables [%s] missing", joined), "")
	}

	cmdArgs := &skel.CmdArgs{
		ContainerID: contID,
		Netns:       netns,
		IfName:      ifName,
		Args:        args,
		Path:        path,
	}
	return cmd, cmdArgs, nil
}
