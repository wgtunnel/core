// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build darwin

package osfirewall

import (
	"net"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/wgtunnel/backend/log"
)

const vmPassRefresh = 2 * time.Second

func listVMPassIfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Debug(tag, "list interfaces: %v", err)
		return nil
	}
	described := make([]vmIface, 0, len(ifaces))
	for _, ifc := range ifaces {
		item := vmIface{name: ifc.Name}
		if strings.HasPrefix(strings.ToLower(ifc.Name), "bridge") {
			item.bridge = true
			item.members = readBridgeMembers(ifc.Name)
		}
		described = append(described, item)
	}
	return vmPassIfaces(described)
}

func readBridgeMembers(name string) []string {
	if !safeIface(name) {
		return nil
	}
	out, err := exec.Command("ifconfig", name).CombinedOutput()
	if err != nil {
		log.Debug(tag, "ifconfig %s: %v", name, err)
		return nil
	}
	return parseBridgeMembers(string(out))
}

func (f *DarwinFirewall) anchorFamilies() (wantV4, wantV6 bool) {
	persist := f.persistKillSwitch.Load()
	wantV4 = f.tunnelReqV4.Load() || persist
	wantV6 = (f.tunnelReqV6.Load() || persist) && f.v6Available
	return wantV4, wantV6
}

func (f *DarwinFirewall) startVMWatchLocked() {
	if f.vmStop != nil {
		return
	}
	stop := make(chan struct{})
	f.vmStop = stop
	go f.vmWatchLoop(stop)
}

func (f *DarwinFirewall) stopVMWatchLocked() {
	if f.vmStop == nil {
		return
	}
	close(f.vmStop)
	f.vmStop = nil
}

func (f *DarwinFirewall) vmWatchLoop(stop <-chan struct{}) {
	t := time.NewTicker(vmPassRefresh)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			f.refreshVMPass()
		}
	}
}

// refreshVMPass runs on every watch tick. It puts the anchor call back when a
// pf reload dropped it, and reloads the anchor when a virtual NIC appears or
// goes away after the kill switch was enabled.
func (f *DarwinFirewall) refreshVMPass() {
	names := listVMPassIfaces()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vmStop == nil {
		return
	}
	wantV4, wantV6 := f.anchorFamilies()
	if !wantV4 && !wantV6 {
		return
	}
	// A failed or rolled back insert would leave the block unattached, so a
	// call inserted here stays even if the reload below fails. The body it
	// calls still holds the last good ruleset.
	inserted, err := f.ensureAnchorCall()
	if err != nil {
		log.Error(tag, "pf anchor call check: %v", err)
		return
	}
	if inserted {
		log.Error(tag, "pf anchor call was missing from the main ruleset, restored")
	}
	if !inserted && slices.Equal(f.vmIfaces, names) {
		return
	}
	prev := f.vmIfaces
	f.vmIfaces = names
	if err := f.loadAnchor(wantV4, wantV6); err != nil {
		f.vmIfaces = prev
		log.Error(tag, "vm pass refresh: %v", err)
		return
	}
	if err := killBlockedPFStates(f.keepLocked()); err != nil {
		log.Error(tag, "vm pass state kill: %v", err)
	}
}
