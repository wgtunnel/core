//go:build android

package tunwrap

import "github.com/wgtunnel/backend/tunwrap/dns"

// killSwitchGate on Android has no live native kill switch because
// it does a full teardown so just a start-time snapshot is sufficient
func killSwitchGate(cfg *dns.TunnelDNSConfig) func() bool {
	enabled := cfg != nil && cfg.KillSwitchEnabled
	return func() bool { return enabled }
}
