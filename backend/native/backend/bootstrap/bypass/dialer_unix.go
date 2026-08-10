//go:build unix && !android

package bypass

import (
	"net"
	"syscall"

	"github.com/wgtunnel/backend/vpn/firewall/mark"
)

func BypassSocket(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark.LinuxBootstrapMarkNum)
}

// Dialer ifIndex unused on Linux
func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	_ = ifIndex
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(BypassSocket)
}
