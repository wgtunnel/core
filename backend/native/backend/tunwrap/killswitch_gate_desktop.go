//go:build !android

package tunwrap

import (
	"github.com/wgtunnel/backend/tunwrap/dns"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall/firewallmgr"
)

// killSwitchGate returns a live check of desktop's kill switch state
// because on desktop kill switch can be enabled and disabled at any time
// when tunnels are running
func killSwitchGate(cfg *dns.TunnelDNSConfig) func() bool {
	return func() bool {
		fw, err := firewallmgr.Get()
		if err != nil {
			return false
		}
		return fw.IsEnabled() && fw.IsPersistent()
	}
}
