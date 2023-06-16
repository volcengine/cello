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
	"os"
)

var (
	endpoint string
	ramRole  string
)

func main() {
	app := &cli.App{
		Name:     "tag-tool",
		Usage:    "convert eni description to tags",
		Version:  "1.0.0",
		Commands: buildCommand(),
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "endpoint", Value: "", Required: true, Destination: &endpoint},
			&cli.StringFlag{Name: "ramRole", Value: "KubernetesNodeRoleForECS", Destination: &ramRole},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
}

func buildCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "tagEni",
			Usage: "convert eni description to tags",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "exec", Value: false},
				&cli.BoolFlag{Name: "vpc-all", Aliases: []string{"v"}, Value: false},
			},
			Action: tagEni,
		},
		{
			Name:  "listTaggedEni",
			Usage: "list tagged eni",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "vpc-all", Aliases: []string{"v"}, Value: false},
			},
			Action: listTaggedEni,
		},
	}
}
