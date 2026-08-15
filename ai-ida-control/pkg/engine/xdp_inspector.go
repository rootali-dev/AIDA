package engine

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

// InterfaceStatus وضعیت کامل یک اینترفیس و اتصال XDP
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

// InspectInterfaces کاوش تمام کارت‌های شبکه و بررسی وجود هوک XDP
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

		// بررسی وضعیت اتصال XDP بر اساس ساختار رسمی netlink.LinkXdp
		if attrs.Xdp != nil && attrs.Xdp.Attached {
			status.IsProtected = true
			status.ProgramID = attrs.Xdp.ProgId

			// تحلیل مد بر اساس AttachMode و بیت‌ماسک Flags هسته لینوکس
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