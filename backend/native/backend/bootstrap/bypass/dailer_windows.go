//go:build windows

package bypass

import (
	"encoding/binary"
	"net"
	"unsafe"

	"github.com/wgtunnel/backend/network"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
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
	return bindFamilies(fd, ifIndex, ifIndex)
}

// bindFamilies sends through the given adapter for each family. Zero leaves that
// family to the routing table.
func bindFamilies(fd uintptr, v4Index, v6Index uint32) error {
	handle := windows.Handle(fd)
	if v4Index != 0 {
		// IP_UNICAST_IF takes the index in network byte order, IPV6_UNICAST_IF in host order.
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v4Index)
		_ = windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, int(*(*uint32)(unsafe.Pointer(&b[0]))))
	}
	if v6Index != 0 {
		_ = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(v6Index))
	}
	return nil
}

// Dialer binds to the physical adapter. The tunnel's routes are already in place while
// peers are resolved, so an unbound socket followed them into the tunnel and timed out
// from the tunnel address.
func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(func(fd uintptr) error {
		if ifIndex != 0 {
			return bindToInterface(fd, ifIndex)
		}
		return bindFamilies(fd, physicalIfIndex(windows.AF_INET), physicalIfIndex(windows.AF_INET6))
	})
}

func physicalIfIndex(family winipcfg.AddressFamily) uint32 {
	route, ok, err := network.PhysicalDefaultRoute(family)
	if err != nil || !ok {
		return 0
	}
	return route.IfIndex
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
