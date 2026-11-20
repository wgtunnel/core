//go:build !android && !linux && !windows

package vpn

import "github.com/amnezia-vpn/amneziawg-go/v3/tun"

// retryCreateAfterStale is true because removeStaleTun can free the name for a second
// CreateTUN.
const retryCreateAfterStale = true

func desktopIfaceExists(ifName string) bool {
	_ = ifName
	return false
}

func removeStaleTun(ifName string) {
	// For macOS closing the tun.Device removes the adapter. A leftover name is
	// recovered on the next CreateTUN
	_ = ifName
}

func cleanupOrphanedDesktopIface(ifName string) {
	_ = ifName
}

func createTUN(ifName string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(ifName, mtu)
}
