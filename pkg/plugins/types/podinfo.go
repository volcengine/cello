package types

const (
	PodInfoVersion10 = "1.0"
)

type PodInfo struct {
	Version           string             `json:"version,omitempty"`
	ResourceMap       *ResourceMap       `json:"resourceMap,omitempty"`
	NetNs             string             `json:"netns,omitempty"`
	NetworkInterfaces []NetworkInterface `json:"networkInterfaces,omitempty"`
}

type ResourceMap struct {
	Containers []*ContainerResourceInfo `json:"containers"`
}

type NetworkInterface struct {
	Name                     string                    `json:"name,omitempty"`
	CNI                      string                    `json:"cni,omitempty"`
	Mac                      string                    `json:"mac,omitempty"`
	IPs                      []string                  `json:"ips,omitempty"`
	NetworkInterfaceResource *NetworkInterfaceResource `json:"networkInterfaceResource,omitempty"`
}

type NetworkInterfaceResource struct {
	Name       string `json:"name,omitempty"`
	DeviceID   string `json:"deviceID,omitempty"`
	PciAddress string `json:"pciAddress,omitempty"`
}
