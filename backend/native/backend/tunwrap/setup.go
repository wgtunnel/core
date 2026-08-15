package tunwrap

import (
	"fmt"

	"github.com/wgtunnel/backend/dns/transport"
	"github.com/wgtunnel/backend/dns/transport/doh"
	"github.com/wgtunnel/backend/dns/transport/dot"
	"github.com/wgtunnel/backend/dns/transport/plain"
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

	needLocal := cfg.DefaultTransport == "local" || len(cfg.LocalSuffixes) > 0
	if needLocal && local == nil {
		return nil, fmt.Errorf("dns: local transport required")
	}

	eng := dns.NewEngine()
	if local != nil {
		eng.RegisterTransport("local", local)
	}

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

	router := dns.NewSimpleRouter(eng, cfg.DefaultTransport)
	if len(cfg.LocalSuffixes) > 0 {
		router.AddRule(dns.Rule{
			Domains:      append([]string(nil), cfg.LocalSuffixes...),
			Transport:    "local",
			DisableCache: true,
		})
	}
	eng.SetRouter(router)
	return eng, nil
}
