package bypass

import "net"

// TunnelDialer binds FakeDNS upstream sockets onto the tunnel so queries
// reach AllowedIPs even when the tunnel is not the default route.
func TunnelDialer() *net.Dialer {
	return NewBypassDialer(bindTunnelSocket)
}
