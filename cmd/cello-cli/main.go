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
	"os"

	"github.com/urfave/cli/v2"

	"github.com/volcengine/cello/pkg/version"
)

var BuildInfo = "master"

const title = "cello-ctl"
const usage = "show cello information"

const baseUrl = "http://cello_debug.socket"

func main() {
	app := &cli.App{
		Name:     title,
		Usage:    usage,
		Version:  fmt.Sprintf("%s\n%s", version.Version, BuildInfo),
		Commands: buildCommand(),
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
}
