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
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/volcengine/cello/types"
)

func buildCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "instanceInfo",
			Usage: "Show info of this instance",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "describeInstanceType", Aliases: []string{"dt"}, Value: false},
			},
			Action: showInstanceInfo,
		},
		{
			Name:   "metadata",
			Usage:  "Show instance metadata",
			Action: showMetadataInfo,
		},
		{
			Name:    "ipam",
			Aliases: []string{"ip"},
			Usage:   "Show information of ipam",
			Subcommands: []*cli.Command{
				{
					Name:    "status",
					Usage:   "Show ipam status",
					Aliases: []string{"stat", "sta"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "resType",
							Value: types.NetResourceTypeEniIp,
							Usage: fmt.Sprintf("type of resource, one of %s %s", types.NetResourceTypeEniIp, types.NetResourceTypeEni),
						},
						&cli.BoolFlag{Name: "json", Value: false, Aliases: []string{"j"}, Usage: "json format"},
					},
					Action: showIPAMStatus,
				},
				{
					Name:   "limit",
					Usage:  "Show instance limit for ipam",
					Action: showIPAMLimit,
				},
			},
		},
		{
			Name:    "pod",
			Aliases: []string{"pd"},
			Usage:   "Show information of pod",
			Subcommands: []*cli.Command{
				{
					Name:      "get",
					Usage:     "Get or list pods",
					ArgsUsage: "[podNameSpace] [podName]",
					Aliases:   []string{"l"},
					Action:    showCelloPods,
					After: func(context *cli.Context) error {
						fmt.Println()
						return nil
					},
				},
			},
		},
		{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "Cello agent config manager",
			Subcommands: []*cli.Command{
				{
					Name:   "get",
					Usage:  "Show config",
					Action: showConfig,
				},
				{
					Name:  "log",
					Usage: "Log config",
					Subcommands: []*cli.Command{
						{
							Name:    "set-level",
							Aliases: []string{"set-level"},
							Usage:   "set log-level",
							Action:  setLogLevel,
						},
					},
				},
				{
					Name:  "subnet",
					Usage: "Subnet config",
					Subcommands: []*cli.Command{
						{
							Name:    "status",
							Aliases: []string{"stat", "sta"},
							Usage:   "show pod subnets status",
							Action:  showPodSubnetStatus,
						},
					},
				},
				{
					Name:    "securityGroup",
					Usage:   "securityGroup config",
					Aliases: []string{"sec"},
					Subcommands: []*cli.Command{
						{
							Name:    "status",
							Aliases: []string{"stat", "sta"},
							Usage:   "show securityGroup status",
							Action:  showSecurityGroupStatus,
						},
					},
				},
			},
		},
	}
}
