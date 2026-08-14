//go:build unix && !android

package bypass

import (
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/wgtunnel/backend/vpn/firewall/mark"
	"golang.org/x/sys/unix"
)

func BypassSocket(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark.LinuxBootstrapMarkNum)
}

func bindToDevice(fd uintptr, ifIndex uint32) error {
	if ifIndex == 0 {
		return nil
	}
	link, err := netlink.LinkByIndex(int(ifIndex))
	if err != nil {
		return err
	}
	return unix.BindToDevice(int(fd), link.Attrs().Name)
}

// Dialer marks sockets so policy routing uses the main table
func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	_ = ifIndex
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(BypassSocket)
}

// NetworkDialer binds to the physical underlay for local DNS, and still marks
// so the kill switch does not drop the query
func NetworkDialer(ifIndex uint32) *net.Dialer {
	return NewBypassDialer(func(fd uintptr) error {
		if err := BypassSocket(fd); err != nil {
			return err
		}
		return bindToDevice(fd, ifIndex)
	})
}
