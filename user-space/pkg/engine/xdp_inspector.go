// SPDX-License-Identifier: Apache-2.0\n// SPDX-License-Identifier: Apache-2.0\npackage engine

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

type InterfaceStatus struct {
	Index       int
	Name        string
	MAC         string
	OperState   string
	MTU         int
	IsProtected bool
	XdpMode     string
	ProgramID   uint32
}

func InspectInterfaces() ([]InterfaceStatus, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to query netlink links: %w", err)
	}

	var results []InterfaceStatus

	for _, link := range links {
		attrs := link.Attrs()
		status := InterfaceStatus{
			Index:       attrs.Index,
			Name:        attrs.Name,
			MAC:         attrs.HardwareAddr.String(),
			OperState:   attrs.OperState.String(),
			MTU:         attrs.MTU,
			IsProtected: false,
			XdpMode:     "NONE",
			ProgramID:   0,
		}

		if attrs.Xdp != nil && attrs.Xdp.Attached {
			status.IsProtected = true
			status.ProgramID = attrs.Xdp.ProgId

			switch attrs.Xdp.AttachMode {
			case 1:
				status.XdpMode = "GENERIC/SKB"
			case 2:
				status.XdpMode = "NATIVE/DRIVER"
			case 3:
				status.XdpMode = "HW_OFFLOAD"
			default:
				if attrs.Xdp.Flags&(1<<1) != 0 {
					status.XdpMode = "GENERIC/SKB"
				} else if attrs.Xdp.Flags&(1<<2) != 0 {
					status.XdpMode = "NATIVE/DRIVER"
				} else if attrs.Xdp.Flags&(1<<3) != 0 {
					status.XdpMode = "HW_OFFLOAD"
				} else {
					status.XdpMode = "ATTACHED"
				}
			}
		}

		results = append(results, status)
	}

	return results, nil
}
