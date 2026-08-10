package tunwrap

import (
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/wgtunnel/backend/dns/transport"
	platform "github.com/wgtunnel/backend/dns/transport/local"
	"github.com/wgtunnel/backend/tunwrap/dns"
	wrap "github.com/wgtunnel/backend/tunwrap/tun"
)

// MaybeWrapTUN returns WrapperTUN when valid dnsConfigJSON is present, otherwise, just returns base or closes base on error
func MaybeWrapTUN(base tun.Device, dnsConfigJSON string) (tun.Device, error) {
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

	engine, err := Setup(cfg, local)
	if err != nil {
		base.Close()
		return nil, err
	}
	if engine == nil {
		return base, nil
	}

	ft, err := wrap.NewWrapperTUN(base, engine, cfg.FakeDNS, cfg.FakeDNSV6, cfg.ForeignDNSPolicy)
	if err != nil {
		_ = engine.Close()
		base.Close()
		return nil, err
	}
	return ft, nil
}

func needsLocal(cfg *dns.TunnelDNSConfig) bool {
	return cfg.DefaultTransport == "local" || len(cfg.LocalSuffixes) > 0
}
