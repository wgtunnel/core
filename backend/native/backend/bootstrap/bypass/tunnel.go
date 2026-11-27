package bypass

import (
	"net"
	"net/netip"
	"slices"
	"syscall"
)

// TunnelDialer binds FakeDNS upstream sockets onto the tunnel so queries reach AllowedIPs
// even when the tunnel is not the default route. On desktop, a split tunnel's upstream
// outside routes is left to the routing table, as any traffic outside its AllowedIPs is
// bound to the tunnel. A full tunnel always binds, so DNS for a family it blocks is dropped rather
// than sent out the physical network, which the Windows kill switch permits for the daemon.
func TunnelDialer(routes []netip.Prefix) *net.Dialer {
	return &net.Dialer{
		Control: func(_, address string, c syscall.RawConn) error {
			if !bindsToTunnel(address, routes) {
				return nil
			}
			var opErr error
			if err := c.Control(func(fd uintptr) { opErr = bindTunnelSocket(fd) }); err != nil {
				return err
			}
			return opErr
		},
	}
}

func bindsToTunnel(address string, routes []netip.Prefix) bool {
	if tunnelOnlyDNS || len(routes) == 0 || slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Bits() == 0 }) {
		return true
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return true
	}
	addr := ap.Addr().Unmap()
	return slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Contains(addr) })
}
