package tunwrap

import (
	"fmt"
	"strings"

	"github.com/wgtunnel/backend/dns/transport"
	"github.com/wgtunnel/backend/dns/transport/doh"
	"github.com/wgtunnel/backend/dns/transport/dot"
	"github.com/wgtunnel/backend/dns/transport/plain"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/tunwrap/dns"
)

// Setup builds the hijack DNS engine.
// local may be nil unless cfg needs local (defaultTransport=="local" or LocalSuffixes).
// dial, when set, is used for doh/dot/plain upstreams (lockdown/proxy netstack).
func Setup(cfg *dns.TunnelDNSConfig, local transport.Transport, dial DialContextFunc) (*dns.Engine, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	splitTunnel := isSplitTunnelMode(cfg)
	needLocal := cfg.DefaultTransport == "local" || len(cfg.LocalSuffixes) > 0 || splitTunnel
	if needLocal && local == nil {
		return nil, fmt.Errorf("dns: local transport required")
	}

	eng := dns.NewEngine()
	if local != nil {
		eng.RegisterTransport("local", local)
	}

	// Tunnel/encrypted transport tag, may equal "local" for all local mode.
	tunnelTransport := cfg.DefaultTransport
	switch cfg.DefaultTransport {
	case "doh":
		t := doh.New(cfg.Upstream, cfg.ServerName)
		t.DialContext = dial
		eng.RegisterTransport("doh", t)
	case "dot":
		t := dot.New(cfg.Upstream, cfg.ServerName)
		t.DialContext = dial
		eng.RegisterTransport("dot", t)
	case "plain":
		t := plain.New(cfg.Upstream, "udp")
		t.DialContext = dial
		eng.RegisterTransport("plain", t)
	case "local":
		// only "local"
	}

	// final transport and optional suffix rules.
	finalTransport := cfg.DefaultTransport
	suffixTransport := "local"
	if splitTunnel {
		// Inverse split handled later
		if tunnelTransport == "local" {
			return nil, fmt.Errorf("dns: splitMode=tunnel requires a non-local defaultTransport")
		}
		finalTransport = "local"
		suffixTransport = tunnelTransport
	}

	router := dns.NewSimpleRouter(eng, finalTransport)
	if len(cfg.LocalSuffixes) > 0 {
		router.AddRule(dns.Rule{
			Domains:      append([]string(nil), cfg.LocalSuffixes...),
			Transport:    suffixTransport,
			DisableCache: true,
		})
		log.Debug(
			"DnsSetup",
			"split suffixes=%v suffixTransport=%s defaultTransport=%s splitMode=%q foreign=%q",
			cfg.LocalSuffixes,
			suffixTransport,
			finalTransport,
			cfg.SplitMode,
			cfg.ForeignDNSPolicy,
		)
	}
	eng.SetRouter(router)
	return eng, nil
}

func isSplitTunnelMode(cfg *dns.TunnelDNSConfig) bool {
	if cfg == nil || len(cfg.LocalSuffixes) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(cfg.SplitMode), "tunnel")
}
