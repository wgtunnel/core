//go:build windows

package bypass

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IP_UNICAST_IF   = 0x1f
	IPV6_UNICAST_IF = 0x1f
)

// BypassSocket is the per socket bias. WFP already permits the daemon
// process, so there is no extra mark to set.
func BypassSocket(fd uintptr) error {
	_ = fd
	return nil
}

func bindToInterface(fd uintptr, ifIndex uint32) error {
	if ifIndex == 0 {
		return nil
	}
	handle := windows.Handle(fd)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ifIndex)
	v4 := int(*(*uint32)(unsafe.Pointer(&b[0])))
	_ = windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, v4)
	_ = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(ifIndex))
	return nil
}

// Dialer is a biased socket only
func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	_ = ifIndex
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(BypassSocket)
}

// NetworkDialer binds local DNS to the underlay adapter
func NetworkDialer(ifIndex uint32) *net.Dialer {
	return NewBypassDialer(func(fd uintptr) error {
		if err := BypassSocket(fd); err != nil {
			return err
		}
		return bindToInterface(fd, ifIndex)
	})
}
