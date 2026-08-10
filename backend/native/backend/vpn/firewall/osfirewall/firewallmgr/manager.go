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

		// defensive cleanup
		if fw.IsEnabled() {
			log.Debug(tag, "Kill switch was left enabled from previous run, disabling...")
			if err := fw.Disable(); err != nil {
				log.Error(tag, "Failed to disable stale kill switch: %v", err)
			}
		}

		instance = fw
	})

	return instance, initErr
}
