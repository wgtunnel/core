//go:build android

package roaming

import "github.com/amnezia-vpn/amneziawg-go/v3/device"

func ApplyRoaming(d *device.Device) {
	d.DisableSomeRoamingForBrokenMobileSemantics()
}
