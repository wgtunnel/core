//go:build linux

package network

import (
	"fmt"

	"github.com/mdlayher/wifi"
)

func wifiInfoForInterface(
	client *wifi.Client,
	ifIndex uint32,
	ifName string,
) (ssid, bssid string, wireless bool, err error) {
	// No nl80211 client, let caller use name fallback
	if client == nil {
		return "", "", false, fmt.Errorf("wifi client unavailable")
	}

	ifaces, err := client.Interfaces()
	if err != nil {
		return "", "", false, fmt.Errorf("wifi interfaces: %w", err)
	}

	var target *wifi.Interface
	for _, iface := range ifaces {
		if uint32(iface.Index) == ifIndex || iface.Name == ifName {
			target = iface
			break
		}
	}
	if target == nil {
		return "", "", false, nil // not a wifi interface
	}

	bss, err := client.BSS(target)
	if err != nil || bss == nil {
		// Wireless interface exists, association details unavailable
		return "", "", true, nil
	}

	ssid = bss.SSID
	if len(bss.BSSID) > 0 {
		bssid = bss.BSSID.String()
	}
	return ssid, bssid, true, nil
}
