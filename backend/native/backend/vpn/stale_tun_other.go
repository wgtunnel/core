//go:build !android && !linux

package vpn

func desktopIfaceExists(ifName string) bool {
	_ = ifName
	return false
}

func removeStaleTun(ifName string) {
	// For Windows and macOS closing the tun.Device removes the adapter. A leftover
	// name is recovered on the next CreateTUN
	_ = ifName
}

func cleanupOrphanedDesktopIface(ifName string) {
	_ = ifName
}
