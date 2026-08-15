package tun

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// UpstreamIPs extracts literal IP destinations from plain FakeDNS upstreams
// so the engine's own UDP/TCP 53 queries can reach WG instead of being
// hijacked again.
func UpstreamIPs(upstreams []string) []netip.Addr {
	var out []netip.Addr
	seen := make(map[netip.Addr]struct{})
	add := func(s string) {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.IsValid() {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for _, raw := range upstreams {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			add(u.Hostname())
			continue
		}
		host, _, err := net.SplitHostPort(raw)
		if err != nil {
			add(raw)
			continue
		}
		add(host)
	}
	return out
}
