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
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"

	cniLog "github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/metrics"
	"github.com/volcengine/cello/pkg/utils/logger"
)

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, cniVersion.All, "Cello CNI")
}

func cmdAdd(args *skel.CmdArgs) error {
	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		cniLog.Log.Infof("CmdAdd time cost:%f Millisecond", duration)
	}()
	cniLog.Log.WithFields(logger.Fields{
		"ContainerId": args.ContainerID,
		"Netns":       args.Netns},
	).Infof("Handle cmd add")

	err := Add(args)
	if err != nil {
		cniLog.Log.WithFields(logger.Fields{
			"Command":     "Add",
			"ContainerId": args.ContainerID,
			"Netns":       args.Netns},
		).Errorf("Handle cmd add failed: %v", err)
	}

	return err
}

func cmdDel(args *skel.CmdArgs) error {
	start := time.Now()
	defer func() {
		duration := metrics.MsSince(start)
		cniLog.Log.Infof("CmdDel time cost:%f Millisecond", duration)
	}()
	cniLog.Log.WithFields(logger.Fields{
		"ContainerId": args.ContainerID,
		"Netns":       args.Netns},
	).Infof("Handle cmd del")
	err := Del(args)
	if err != nil {
		cniLog.Log.WithFields(
			logger.Fields{
				"Command":     "Del",
				"ContainerId": args.ContainerID,
				"Netns":       args.Netns,
			}).Infof("Handle cmd del failed: %s", err.Error())
	}
	return err
}

func cmdCheck(args *skel.CmdArgs) error {
	err := Check(args)
	if err != nil {
		cniLog.Log.WithFields(
			logger.Fields{
				"Command":     "Check",
				"ContainerId": args.ContainerID,
				"Netns":       args.Netns,
			}).Infof("Handle cmd del failed: %s", err.Error())
	}
	return err
}
