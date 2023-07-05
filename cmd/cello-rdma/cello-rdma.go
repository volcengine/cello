package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"

	celloRdma "github.com/volcengine/cello/pkg/cni/plugins/cello-rdma"
)

func main() {
	skel.PluginMain(celloRdma.CmdAdd, celloRdma.CmdCheck, celloRdma.CmdDel, cniVersion.All, "Cello CNI for RDMA")
}
