//go:build darwin

package bypass

import (
	"net"

	"github.com/wgtunnel/backend/network"
	"github.com/wgtunnel/backend/vpn/firewall/mark"
	"golang.org/x/sys/unix"
)

// BypassSocket marks the socket with mark.DarwinBootstrapTOS via IP_TOS/IPV6_TCLASS
func BypassSocket(fd uintptr) error {
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, mark.DarwinBootstrapTOS)
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, mark.DarwinBootstrapTOS)
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
		if err := BypassSocket(fd); err != nil {
			return err
		}
		idx := ifIndex
		if idx == 0 {
			idx = defaultPhysicalIfIndex()
		}
		return bindToDevice(fd, idx)
	})
}

func NetworkDialer(ifIndex uint32) *net.Dialer {
	return NewBypassDialer(func(fd uintptr) error {
		if err := BypassSocket(fd); err != nil {
			return err
		}
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
