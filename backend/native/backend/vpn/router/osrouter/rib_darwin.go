//go:build darwin

package osrouter

import (
	"math/bits"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// routeOwners maps each prefix in the kernel routing table to the interface indexes
// holding a route for exactly it. Unlike `route get`, it sees interface-scoped routes:
// a LAN that is not the primary network has a scoped connected route, which `route get`
// skips in favor of the default route. Host entries cloned from another route (ARP and
// path caches) are not routes anyone added, so they are listed apart in cloned.
func routeOwners() (owners map[netip.Prefix][]int, cloned map[netip.Prefix]bool, err error) {
	owners = map[netip.Prefix][]int{}
	cloned = map[netip.Prefix]bool{}
	for _, af := range []int{unix.AF_INET, unix.AF_INET6} {
		b, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, nil, err
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range msgs {
			rm, ok := m.(*route.RouteMessage)
			if !ok || len(rm.Addrs) <= unix.RTAX_NETMASK {
				continue
			}
			dst, ok := ribAddr(rm.Addrs[unix.RTAX_DST])
			if !ok {
				continue
			}
			n := dst.BitLen()
			if rm.Flags&unix.RTF_HOST == 0 {
				n = ribMaskBits(rm.Addrs[unix.RTAX_NETMASK])
			}
			p := netip.PrefixFrom(dst, n).Masked()
			if rm.Flags&unix.RTF_WASCLONED != 0 {
				cloned[p] = true
				continue
			}
			owners[p] = append(owners[p], rm.Index)
		}
	}
	return owners, cloned, nil
}

func ribAddr(a route.Addr) (netip.Addr, bool) {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP), true
	}
	return netip.Addr{}, false
}

func ribMaskBits(a route.Addr) int {
	var b []byte
	switch a := a.(type) {
	case *route.Inet4Addr:
		b = a.IP[:]
	case *route.Inet6Addr:
		b = a.IP[:]
	default:
		return 0
	}
	n := 0
	for _, x := range b {
		n += bits.OnesCount8(x)
	}
	return n
}
