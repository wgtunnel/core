package osrouter

import (
	"net"
	"net/netip"
	"slices"
)

// endpointNeedsProtection reports whether a peer endpoint needs a route through the
// physical gateway to keep the tunnel's own packets out of the tunnel. An endpoint on a
// directly connected subnet is reached over that link, whose route is more specific than
// the tunnel's. A private endpoint anywhere else, such as a server on another LAN behind
// the gateway, needs the route as much as a public one.
func endpointNeedsProtection(p netip.Prefix, tunnelAddrs []netip.Prefix) bool {
	if !p.IsValid() || p.Addr().IsLinkLocalUnicast() {
		return false
	}
	return !onConnectedSubnet(p.Addr(), tunnelAddrs)
}

// onConnectedSubnet reports whether addr is inside the subnet of an up interface other
// than the tunnel, which is the one holding one of tunnelAddrs.
func onConnectedSubnet(addr netip.Addr, tunnelAddrs []netip.Prefix) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return addr.IsPrivate()
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		prefixes := interfacePrefixes(ifc)
		if holdsTunnelAddr(prefixes, tunnelAddrs) {
			continue
		}
		for _, p := range prefixes {
			if p.Masked().Contains(addr) {
				return true
			}
		}
	}
	return false
}

// interfacePrefixes lists an interface's addresses with their prefix lengths.
func interfacePrefixes(ifc net.Interface) []netip.Prefix {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ones, _ := ipn.Mask.Size()
		out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return out
}

func holdsTunnelAddr(prefixes, tunnelAddrs []netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool {
		return slices.ContainsFunc(tunnelAddrs, func(t netip.Prefix) bool { return t.Addr() == p.Addr() })
	})
}
