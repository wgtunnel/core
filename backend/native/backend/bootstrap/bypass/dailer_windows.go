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

func BypassSocket(ifIndex uint32) SocketBypass {
	return func(fd uintptr) error {
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
}

func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(BypassSocket(ifIndex))
}
