//go:build !android

package killswitch

/*
#include <stdlib.h>
*/
import "C"

import (
	"net/netip"
	"strings"

	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall/firewallmgr"
)

const tag = "KillSwitch"

//export setKillSwitch
func setKillSwitch(enabled C.int) C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "Failed to get firewall: %v", err)
		return -1
	}
	if enabled == 1 {
		fw.SetPersist(true)
		if err := fw.Enable(); err != nil {
			log.Error(tag, "Failed to enable kill switch: %v", err)
			return -1
		}
		log.Debug(tag, "Kill switch enabled")
	} else {
		if err := fw.Disable(); err != nil {
			log.Error(tag, "Failed to disable kill switch: %v", err)
			return -1
		}
		log.Debug(tag, "Kill switch disabled")
	}
	return C.int(enabled)
}

//export getKillSwitchStatus
func getKillSwitchStatus() C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		return 0
	}
	if fw.IsEnabled() && fw.IsPersistent() {
		return 1
	}
	return 0
}

// cidrsCSV: comma-separated prefixes ("192.168.0.0/16,10.0.0.0/8"). Empty clears bypasses.
//
//export setKillSwitchAllowedNetworks
func setKillSwitchAllowedNetworks(cidrsCSV *C.char) C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "Failed to get firewall: %v", err)
		return -1
	}
	if !fw.IsEnabled() {
		log.Error(tag, "Firewall is not active")
		return -1
	}

	raw := ""
	if cidrsCSV != nil {
		raw = C.GoString(cidrsCSV)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if err := fw.RemoveLocalNetworks(); err != nil {
			log.Error(tag, "RemoveLocalNetworks: %v", err)
			return -1
		}
		log.Debug(tag, "Cleared allowed networks")
		return 0
	}

	prefixes, err := parsePrefixes(raw)
	if err != nil {
		log.Error(tag, "parse allowed networks: %v", err)
		return -1
	}
	if err := fw.AllowLocalNetworks(prefixes); err != nil {
		log.Error(tag, "AllowLocalNetworks: %v", err)
		return -1
	}
	log.Debug(tag, "Allowed networks set: %v", prefixes)
	return 0
}

//export getKillSwitchAllowedNetworksEnabled
func getKillSwitchAllowedNetworksEnabled() C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		return 0
	}
	if fw.IsAllowLocalNetworksEnabled() {
		return 1
	}
	return 0
}

func parsePrefixes(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			// allow bare IP to /32 or /128
			addr, aerr := netip.ParseAddr(part)
			if aerr != nil {
				return nil, err
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			p = netip.PrefixFrom(addr, bits)
		}
		out = append(out, p)
	}
	return out, nil
}
