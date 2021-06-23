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
	"sort"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/urfave/cli/v2"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"

	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/daemon"
	"github.com/volcengine/cello/pkg/pool"
	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
	celloTypes "github.com/volcengine/cello/types"
)

func showInstanceInfo(c *cli.Context) error {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.EcsMetaInfoGetPath)
	api := "DescribeInstances"
	var buf interface{}
	instance := &ecs.DescribeInstancesOutput{}
	instanceType := &ecs.DescribeInstanceTypesOutput{}
	buf = &instance
	if c.Bool("describeInstanceType") {
		api = "DescribeInstanceTypes"
		buf = &instanceType
	}
	err := debugClientGet(url, buf, AdditionArg{
		Key:   "api",
		Value: api,
	})
	if err != nil {
		return err
	}
	fmt.Printf("InstanceInfo: \n%s\n", PrettyJson(buf))
	return nil
}

func showConfig(c *cli.Context) error {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.ConfigGetPath)
	cfg := &config.Config{}
	err := debugClientGet(url, &cfg)
	if err != nil {
		return err
	}
	fmt.Printf("Config: \n%s\n", PrettyJson(cfg))
	return nil
}

func showIPAMLimit(c *cli.Context) error {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.IPAMLimitGetPath)
	limit := helper.InstanceLimitsAttr{}
	err := debugClientGet(url, &limit)
	if err != nil {
		return err
	}
	fmt.Printf("Limit: \n%s\n", PrettyJson(limit))
	return nil
}

func showIPAMStatus(c *cli.Context) error {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.IPAMSnapshotGetPath)
	snap := map[string]struct {
		Pool map[string]celloTypes.NetResourceSnapshot `json:"pool,omitempty"`
		Meta map[string]celloTypes.NetResourceSnapshot `json:"meta,omitempty"`
	}{}

	err := debugClientGet(url, &snap)
	if err != nil {
		return err
	}

	if c.Bool("json") {
		url = fmt.Sprintf("%s%s", baseUrl, daemon.IPAMStatusGetPath)
		status := map[string]pool.Status{}
		err = debugClientGet(url, &status)
		if err != nil {
			return err
		}
		info := struct {
			pool.Status
			Stat map[string]struct {
				Pool map[string]celloTypes.NetResourceSnapshot `json:"pool,omitempty"`
				Meta map[string]celloTypes.NetResourceSnapshot `json:"meta,omitempty"`
			}
		}{
			Status: status[c.String("resType")],
			Stat:   snap,
		}
		fmt.Printf("%s\n", PrettyJson(info))
		return nil
	}

	tableData := pterm.TableData{
		{
			"Index",
			"Type",
			"Status",
			"ResId",
			"EniMac",
			"Owner",
			"MetaResId",
		},
	}

	exec := func(resType string) {
		res := snap[resType]
		data := res.Pool
		meta := res.Meta
		var array []celloTypes.NetResourceSnapshot
		for _, d := range data {
			array = append(array, d)
		}
		sort.Slice(array, func(i, j int) bool {
			if array[i].Status == array[j].Status {
				return array[i].ID > array[j].ID
			}
			return array[i].Status > array[j].Status
		})

		i := 0
		for _, d := range array {
			clr := pterm.FgDefault
			switch d.Status {
			case celloTypes.ResStatusAvailable:
				clr = pterm.FgLightGreen
			case celloTypes.ResStatusInvalid:
				clr = pterm.FgLightRed
			}
			metaResId := ""
			status := d.Status
			if m, exist := meta[d.ID]; exist {
				if d.Status != m.Status {
					clr = pterm.FgLightRed
					status = celloTypes.ResStatus(fmt.Sprintf("%s/%s", d.Status, m.Status))
				}
				metaResId = m.ID
				delete(meta, d.ID)
			} else {
				clr = pterm.FgLightRed
				status = celloTypes.ResStatus(fmt.Sprintf("%s/%s", d.Status, celloTypes.ResStatusInvalid))
			}
			row := []string{
				clr.Sprint(i),
				clr.Sprint(d.Type),
				clr.Sprint(status),
				clr.Sprint(d.ID),
				clr.Sprint(d.ENIMac),
				clr.Sprint(d.Owner),
				clr.Sprint(metaResId),
			}
			tableData = append(tableData, row)
			i++
		}

		clr := pterm.FgLightRed
		for _, d := range meta {
			row := []string{
				clr.Sprint(i),
				clr.Sprint(d.Type),
				clr.Sprint(d.Status),
				clr.Sprint(d.ID),
				clr.Sprint(d.ENIMac),
				clr.Sprint(d.Owner),
				clr.Sprint(d.ID),
			}
			tableData = append(tableData, row)
			i++
		}
	}
	exec(c.String("resType"))

	if err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render(); err != nil {
		return err
	}
	return nil
}

func listPods() ([]*celloTypes.Pod, error) {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.PodsGetPath)
	var pods []*celloTypes.Pod
	err := debugClientGet(url, &pods)
	if err != nil {
		return nil, err
	}
	return pods, nil
}

func getPod(podNameSpace, podName string) (*celloTypes.Pod, error) {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.PodsGetPath)
	var pods *celloTypes.Pod
	err := debugClientGet(url, &pods,
		AdditionArg{Key: "podNameSpace", Value: podNameSpace},
		AdditionArg{Key: "podName", Value: podName})
	if err != nil {
		return nil, err
	}
	return pods, nil
}

func showCelloPods(c *cli.Context) error {
	switch c.NArg() {
	case 0:
		pods, err := listPods()
		if err != nil {
			return fmt.Errorf("list pods failed: %s", err.Error())
		}
		for i, pod := range pods {
			fmt.Printf("[%d: %s/%s]:\n%s\n", i, pod.Namespace, pod.Name, PrettyJson(pod))
		}
	case 1:
		pod, err := getPod("default", c.Args().Get(0))
		if err != nil {
			return fmt.Errorf("get pod failed: %s", err.Error())
		}
		if pod.Namespace == "" && pod.Name == "" {
			return fmt.Errorf("not Found")
		}
		fmt.Printf("[%s/%s]:\n%s\n", pod.Namespace, pod.Name, PrettyJson(pod))
	case 2:
		pod, err := getPod(c.Args().Get(0), c.Args().Get(1))
		if err != nil {
			return fmt.Errorf("get pod failed: %s", err.Error())
		}
		if pod.Namespace == "" && pod.Name == "" {
			return fmt.Errorf("not Found")
		}
		fmt.Printf("[%s/%s]:\n%s\n", pod.Namespace, pod.Name, PrettyJson(pod))
	default:
		return fmt.Errorf("invalid Args")
	}
	return nil
}

func setLogLevel(c *cli.Context) error {
	if len(c.Args().Slice()) != 1 {
		return fmt.Errorf("argment num invalid, expect 1")
	}
	level := c.Args().Slice()[0]
	url := fmt.Sprintf("%s%s", baseUrl, daemon.ConfigLogLevelSetPath)
	err := debugClientGet(url, nil, AdditionArg{Key: "logLevel", Value: level})
	if err != nil {
		return fmt.Errorf("failed to set log level %s, err: %v", level, err)
	}
	fmt.Printf("set log level to %s\n", level)
	return nil
}

func showPodSubnetStatus(c *cli.Context) error {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.ConfigSubnetStatusGetPath)
	stat := &helper.Status{}
	err := debugClientGet(url, &stat)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", PrettyJson(stat))
	return nil
}

func showSecurityGroupStatus(c *cli.Context) error {
	url := fmt.Sprintf("%s%s", baseUrl, daemon.ConfigSecurityGrpStatusGetPath)
	var stat []string
	err := debugClientGet(url, &stat)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", PrettyJson(stat))
	return nil
}

const (
	metadataLevelVPC              = 0
	metadataLevelVPCAttr          = 1
	metadataLevelENI              = 1
	metadataLevelENIAttribute     = 2
	metadataLevelENIAttributeItem = 3
)

func printKV(key, value string) string {
	return fmt.Sprintf("%s: %s", key, pterm.ThemeDefault.DefaultText.Sprint(value))
}

func showMetadataInfo(c *cli.Context) error {
	getter := metadata.NewEC2MetadataWrapper(metadata.New())
	ctx := context.Background()
	leveledList := pterm.LeveledList{}

	vpcId, err := getter.GetVpcId(ctx)
	if err != nil {
		return err
	}
	vpcCidr, err := getter.GetVpcCidr(ctx)
	if err != nil {
		return err
	}

	leveledList = append(leveledList, pterm.LeveledListItem{
		Level: metadataLevelVPC,
		Text:  printKV("vpc", vpcId),
	}, pterm.LeveledListItem{
		Level: metadataLevelVPCAttr,
		Text:  printKV("cidr", vpcCidr),
	})

	eniMacs, err := getter.GetENIsMacs(ctx)
	if err != nil {
		return err
	}

	primaryENIMac, err := getter.GetPrimaryENIMac(ctx)
	if err != nil {
		return err
	}

	sort.Slice(eniMacs, func(i, j int) bool {
		return eniMacs[i] == primaryENIMac
	})

	for _, eniMac := range eniMacs {
		isPrimary := eniMac == primaryENIMac

		id, err := getter.GetENIID(ctx, eniMac)
		if err != nil {
			return err
		}
		subnetId, err := getter.GetENISubnetID(ctx, eniMac)
		if err != nil {
			return err
		}
		subnetCidr, err := getter.GetENISubnetCIDR(ctx, eniMac)
		if err != nil {
			return err
		}
		primaryIP, err := getter.GetENIPrimaryIP(ctx, eniMac)
		if err != nil {
			return err
		}
		privateIpv4s, err := getter.GetENIPrivateIPv4s(ctx, eniMac)
		if err != nil {
			return err
		}

		leveledList = append(leveledList,
			pterm.LeveledListItem{
				Level: metadataLevelENI,
				Text:  printKV("eni", eniMac),
			},
			pterm.LeveledListItem{
				Level: metadataLevelENIAttribute,
				Text:  printKV("id", id),
			},
			pterm.LeveledListItem{
				Level: metadataLevelENIAttribute,
				Text:  printKV("isPrimary", fmt.Sprintf("%t", isPrimary)),
			},
			pterm.LeveledListItem{
				Level: metadataLevelENIAttribute,
				Text:  printKV("subnetId", subnetId),
			},
			pterm.LeveledListItem{
				Level: metadataLevelENIAttribute,
				Text:  printKV("subnetCidr", subnetCidr.String()),
			},
			pterm.LeveledListItem{
				Level: metadataLevelENIAttribute,
				Text:  printKV("primaryIP", primaryIP.String()),
			},
		)
		if len(privateIpv4s) > 0 {
			leveledList = append(leveledList,
				pterm.LeveledListItem{
					Level: metadataLevelENIAttribute,
					Text:  "privateIpv4s",
				},
			)
			sort.Slice(privateIpv4s, func(i, j int) bool {
				return privateIpv4s[i].String() < privateIpv4s[j].String()
			})
			for _, addr := range privateIpv4s {
				if addr.Equal(primaryIP) {
					continue
				}
				leveledList = append(leveledList,
					pterm.LeveledListItem{
						Level: metadataLevelENIAttributeItem,
						Text:  addr.String(),
					},
				)
			}
		}
	}

	tree := putils.TreeFromLeveledList(leveledList)
	return pterm.DefaultTree.
		WithTextStyle(&pterm.ThemeDefault.BarLabelStyle).
		WithRoot(tree).
		Render()
}
