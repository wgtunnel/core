package firewallmgr

import (
	"sync"

	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall"
)

var (
	instance firewall.Firewall
	once     sync.Once
	initErr  error
)

const tag = "FirewallManager"

func Get() (firewall.Firewall, error) {
	once.Do(func() {
		var fw firewall.Firewall
		fw, initErr = osfirewall.New()
		if initErr != nil {
			return
		}

		// Leftover rules stay until the caller takes them over or calls Disable.
		if fw.HasLeftoverRules() {
			log.Debug(tag, "Kill switch rules from a previous run are still enforced")
		}

		instance = fw
	})

	return instance, initErr
}
