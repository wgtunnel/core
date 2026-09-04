//go:build !android && linux

package vpn

import (
	"github.com/vishvananda/netlink"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall/firewallmgr"
	"github.com/wgtunnel/backend/vpn/router/osrouter"
)

func desktopIfaceExists(ifName string) bool {
	_, err := netlink.LinkByName(ifName)
	return err == nil
}

// removeStaleTun deletes a leftover kernel TUN by name
func removeStaleTun(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	if err := netlink.LinkDel(link); err != nil {
		log.Error(tag, "remove stale tun %s: %v", ifName, err)
		return
	}
	log.Debug(tag, "removed stale tun %s", ifName)
}

// cleanupOrphanedDesktopIface drops leftover routes, policy rules, and tunnel
// nftables bypasses when destroyInterface has no pending router (JNI key miss
// or a previous process crashed after applying them)
func cleanupOrphanedDesktopIface(ifName string) {
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Error(tag, "orphan cleanup firewall: %v", err)
		return
	}
	rt, err := osrouter.New(ifName, fw, nil)
	if err != nil {
		log.Error(tag, "orphan cleanup router: %v", err)
		return
	}
	if err := rt.Close(); err != nil {
		log.Error(tag, "orphan cleanup close %s: %v", ifName, err)
	}
}
