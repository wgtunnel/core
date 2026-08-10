//go:build !android

package local

import (
	"net"
	"strings"
	"time"

	"github.com/wgtunnel/backend/bootstrap/bypass"
	"github.com/wgtunnel/backend/dns/transport"
	"github.com/wgtunnel/backend/network"
)

// NewLocalTransport builds local DNS from network.Monitor underlay
func NewLocalTransport() transport.Transport {
	_ = network.StartMonitor()
	mon := network.GetMonitor()
	u := NewUnderlayDNS()

	info := mon.Current()
	u.Update(normalizeServers(info.DNSServers), info.IfIndex)

	dr := &desktopResolver{
		underlay: u,
		dialer:   bypass.Dialer(true, info.IfIndex),
		timeout:  5 * time.Second,
	}

	mon.Notify(func(info network.NetworkInfo) {
		u.Update(normalizeServers(info.DNSServers), info.IfIndex)
		dr.SetDialer(bypass.Dialer(true, info.IfIndex))
	})

	t := New(dr)
	t.SetNetworkHandleFunc(func() int64 { return int64(u.IfIndex()) })
	return t
}

func normalizeServers(servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		out = append(out, s)
	}
	return out
}
