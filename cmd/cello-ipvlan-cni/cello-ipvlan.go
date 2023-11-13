package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"

	"github.com/volcengine/cello/pkg/plugins/cni/cello-ipvlan"
)

func main() {
	skel.PluginMain(cello_ipvlan.CmdAdd, cello_ipvlan.CmdCheck, cello_ipvlan.CmdDel, cniVersion.All, "Cello-lite CNI")

}
