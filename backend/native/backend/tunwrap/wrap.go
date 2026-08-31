package tunwrap

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/wgtunnel/backend/bootstrap/bypass"
	"github.com/wgtunnel/backend/dns/transport"
	platform "github.com/wgtunnel/backend/dns/transport/local"
	"github.com/wgtunnel/backend/tunwrap/dns"
	wrap "github.com/wgtunnel/backend/tunwrap/tun"
)

// DialContextFunc dials through the tunnel stack (netstack) or the OS.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// MaybeWrapTUN wraps with OS-dialed upstreams bound to the tunnel network
func MaybeWrapTUN(base tun.Device, dnsConfigJSON string) (tun.Device, error) {
	return MaybeWrapTUNDial(base, dnsConfigJSON, bypass.TunnelDialer().DialContext)
}

// MaybeWrapTUNDial is MaybeWrapTUN with an optional tunnel dialer so FakeDNS
// upstream queries go through WG (netstack) or the tunnel-bound OS dialer.
func MaybeWrapTUNDial(base tun.Device, dnsConfigJSON string, dial DialContextFunc) (tun.Device, error) {
	if strings.TrimSpace(dnsConfigJSON) == "" {
		return base, nil
	}
	cfg, err := dns.ParseTunnelDNSConfig(dnsConfigJSON)
	if err != nil {
		base.Close()
		return nil, err
	}
	if cfg == nil {
		return base, nil
	}

	var local transport.Transport
	if needsLocal(cfg) {
		local = platform.NewLocalTransport()
	}

	engine, err := Setup(cfg, local, dial)
	if err != nil {
		base.Close()
		return nil, err
	}
	if engine == nil {
		return base, nil
	}

	// Setting to prevent repeat hijacking of plain tunnel dns for the configured addresses
	var passthrough []netip.Addr
	if cfg.DefaultTransport == "plain" {
		passthrough = wrap.UpstreamIPs(cfg.Upstream)
	}

	ft, err := wrap.NewWrapperTUN(
		base,
		engine,
		cfg.FakeDNS,
		cfg.FakeDNSV6,
		cfg.ForeignDNSPolicy,
		cfg.LocalSuffixes,
		passthrough,
	)
	if err != nil {
		_ = engine.Close()
		base.Close()
		return nil, err
	}
	return ft, nil
}

func needsLocal(cfg *dns.TunnelDNSConfig) bool {
	if cfg == nil {
		return false
	}
	if cfg.DefaultTransport == "local" || len(cfg.LocalSuffixes) > 0 {
		return true
	}
	// Inverse split always needs local
	return strings.EqualFold(strings.TrimSpace(cfg.SplitMode), "tunnel")
}
