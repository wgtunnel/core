//go:build !android && windows

package vpn

import (
	"crypto/sha256"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
)

// retryCreateAfterStale is false because removeStaleTun cannot remove anything on Windows,
// so a second CreateTUN right away hits the same adapter and blocks for another Wintun
// timeout.
const retryCreateAfterStale = false

func desktopIfaceExists(ifName string) bool {
	_ = ifName
	return false
}

func removeStaleTun(ifName string) {
	// Closing the tun.Device removes the Wintun adapter. A leftover name is recovered
	// on the next CreateTUN
	_ = ifName
}

func cleanupOrphanedDesktopIface(ifName string) {
	_ = ifName
}

// createTUN creates the Wintun adapter for ifName with a stable GUID, so every connect of the
// same tunnel reuses one adapter identity. CreateTUN's default nil GUID made Windows create a new
// network profile on every connect.
//
// A failure is not retried. This runs inside the connect call, under locks a disconnect also
// needs, so a retry would hold the disconnect for as long as it ran.
func createTUN(ifName string, mtu int) (tun.Device, error) {
	return tun.CreateTUNWithRequestedGUID(ifName, deterministicAdapterGUID(ifName), mtu)
}

func deterministicAdapterGUID(ifName string) *windows.GUID {
	sum := sha256.Sum256([]byte("wgtunnel-wintun-adapter/" + ifName))
	return &windows.GUID{
		Data1: uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3]),
		Data2: uint16(sum[4])<<8 | uint16(sum[5]),
		Data3: uint16(sum[6])<<8 | uint16(sum[7]),
		Data4: [8]byte{sum[8], sum[9], sum[10], sum[11], sum[12], sum[13], sum[14], sum[15]},
	}
}
