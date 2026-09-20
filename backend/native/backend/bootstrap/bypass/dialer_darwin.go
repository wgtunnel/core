//go:build darwin

package bypass

import (
	"net"

	"github.com/wgtunnel/backend/network"
	"golang.org/x/sys/unix"
)

// BypassSocket is a no-op: macOS has no fwmark. Underlay exclusion is
// IP_BOUND_IF plus pf pass-to underlay DNS / peer endpoints.
func BypassSocket(fd uintptr) error {
	_ = fd
	return nil
}

func bindToDevice(fd uintptr, ifIndex uint32) error {
	if ifIndex == 0 {
		return nil
	}
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(ifIndex))
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(ifIndex))
	return nil
}

func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(func(fd uintptr) error {
		idx := ifIndex
		if idx == 0 {
			idx = defaultPhysicalIfIndex()
		}
		return bindToDevice(fd, idx)
	})
}

func NetworkDialer(ifIndex uint32) *net.Dialer {
	return NewBypassDialer(func(fd uintptr) error {
		return bindToDevice(fd, ifIndex)
	})
}

func defaultPhysicalIfIndex() uint32 {
	d := network.LookupPhysicalDefault4()
	if d.IfIndex != 0 {
		return d.IfIndex
	}
	return network.LookupPhysicalDefault6().IfIndex
}
