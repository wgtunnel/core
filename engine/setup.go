package engine

import (
	"fmt"

	"github.com/wgtunnel/core/engine/dns"
	"github.com/wgtunnel/core/engine/dns/transport/doh"
	"github.com/wgtunnel/core/engine/dns/transport/dot"
	"github.com/wgtunnel/core/engine/dns/transport/plain"
)

// SetupConfig builds an Engine from a pre-resolved TunnelDNSConfig
// Local is optional, but required when default transport is local or LocalSuffixes is not empty
type SetupConfig struct {
	Config *dns.TunnelDNSConfig
	Local  dns.Transport
}

// SetupTunnelDNSEngine returns a ready Engine, or (nil, nil) when Config is nil
func SetupTunnelDNSEngine(sc SetupConfig) (*dns.Engine, error) {
	cfg := sc.Config
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	needLocal := cfg.DefaultTransport == "local" || len(cfg.LocalSuffixes) > 0
	if needLocal && sc.Local == nil {
		return nil, fmt.Errorf("dns: local transport required for defaultTransport=%q or local suffixes", cfg.DefaultTransport)
	}

	engine := dns.NewEngine()
	if sc.Local != nil {
		engine.RegisterTransport("local", sc.Local)
	}

	switch cfg.DefaultTransport {
	case "doh":
		engine.RegisterTransport("doh", doh.New(cfg.Upstream[0], cfg.ServerName))

	case "dot":
		engine.RegisterTransport("dot", dot.New(cfg.Upstream, cfg.ServerName))

	case "plain":
		engine.RegisterTransport("plain", plain.New(cfg.Upstream, "udp"))

	case "local":
		// only local
	}

	router := dns.NewSimpleRouter(engine, cfg.DefaultTransport)
	if len(cfg.LocalSuffixes) > 0 {
		router.AddRule(dns.Rule{
			Domains:      append([]string(nil), cfg.LocalSuffixes...),
			Transport:    "local",
			DisableCache: true, // disable cache for local
		})
	}
	engine.SetRouter(router)
	return engine, nil
}
