//go:build !android

package killswitch

/*
#include <stdlib.h>
*/
import "C"

import (
	"net/netip"
	"strings"

	"github.com/wgtunnel/backend/instance"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall/firewallmgr"
)

const tag = "KillSwitch"

// setInstanceName names this install's firewall rules, so a beta and a release install keep
// theirs apart. It must run before the firewall is first used.
//
//export setInstanceName
func setInstanceName(name *C.char) C.int {
	if err := instance.Set(C.GoString(name)); err != nil {
		log.Error(tag, "Failed to set instance name: %v", err)
		return -1
	}
	return 0
}

//export setKillSwitch
func setKillSwitch(enabled C.int) C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "Failed to get firewall: %v", err)
		return -1
	}
	if enabled == 1 {
		// SetIndependentLockdown sets the persist flag itself.
		if err := fw.SetIndependentLockdown(true); err != nil {
			log.Error(tag, "Failed to enable kill switch: %v", err)
			return -1
		}
		log.Debug(tag, "Kill switch enabled")
	} else {
		// Releases enforcement for any family the active tunnel doesn't independently
		// require, and clears the persist flag
		if err := fw.SetIndependentLockdown(false); err != nil {
			log.Error(tag, "Failed to disable kill switch: %v", err)
			return -1
		}
		log.Debug(tag, "Kill switch disabled")
	}
	return C.int(enabled)
}

// hasLeftoverKillSwitch is 1 when an earlier daemon left kill switch rules enforced.
//
//export hasLeftoverKillSwitch
func hasLeftoverKillSwitch() C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		return 0
	}
	if fw.HasLeftoverRules() {
		return 1
	}
	return 0
}

// releaseKillSwitch keeps the current rules enforced after this process exits. With
// acrossReboot set, Windows keeps them through a reboot too.
//
//export releaseKillSwitch
func releaseKillSwitch(acrossReboot C.int) C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "Failed to get firewall: %v", err)
		return -1
	}
	if err := fw.Release(acrossReboot == 1); err != nil {
		log.Error(tag, "Failed to release kill switch: %v", err)
		return -1
	}
	return 0
}

// purgeKillSwitch removes every kill switch rule, including ones an earlier daemon left.
//
//export purgeKillSwitch
func purgeKillSwitch() C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "Failed to get firewall: %v", err)
		return -1
	}
	if err := fw.Disable(); err != nil {
		log.Error(tag, "Failed to purge kill switch: %v", err)
		return -1
	}
	return 0
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
// A Go string matches the C side's struct go_string. A *C.char only worked where the
// struct is passed in registers, and read the struct itself as text on Windows x64.
//
//export setKillSwitchAllowedNetworks
func setKillSwitchAllowedNetworks(cidrsCSV string) C.int {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "Failed to get firewall: %v", err)
		return -1
	}
	if !fw.IsEnabled() {
		log.Error(tag, "Firewall is not active")
		return -1
	}

	// The JNI side releases the buffer after the call returns.
	raw := strings.TrimSpace(strings.Clone(cidrsCSV))
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
