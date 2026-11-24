// Copyright (c) 2026 Zane Schepke / WG Tunnel
//
// Portions of this file are derived from Tailscale
// Copyright (c) Tailscale Inc & contributors
// Licensed under the BSD 3-Clause License
// See NOTICE and LICENSES/BSD-3-Clause.txt in the project root

//go:build darwin

package osfirewall

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wgtunnel/backend/instance"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/mark"
	"golang.org/x/net/nettest"
)

const (
	tag = "Firewall"
)

// Named after the instance in New, so a beta install's rules never touch release's. Release
// keeps the names it always had.
var (
	// Top-level anchor call inserted into the live main ruleset. A sub-anchor
	// under com.apple/* is only evaluated when that wildcard is already loaded.
	pfAnchorName = instance.Default
	// Previous name, flushed so an upgrade does not leave it under Apple's wildcard.
	pfLegacyAnchorName = "com.apple/" + instance.Default
	// pf enable references a released firewall still holds. /var/run is cleared on boot,
	// as are pf rules and references.
	pfTokenFile = "/var/run/" + instance.Default + "-pf-tokens"
)

func useInstanceNames() {
	n := instance.Name()
	pfAnchorName = n
	pfLegacyAnchorName = "com.apple/" + n
	pfTokenFile = "/var/run/" + n + "-pf-tokens"
}

type DarwinFirewall struct {
	mu sync.Mutex

	tunName    string
	listenPort uint16
	localNets  []netip.Prefix
	peerPass   []netip.Prefix

	v6Available bool

	tunnelReqV4       atomic.Bool
	tunnelReqV6       atomic.Bool
	persistKillSwitch atomic.Bool

	blockedV4 atomic.Bool
	blockedV6 atomic.Bool

	pfToken string

	// anchor rules an earlier process left, until taken over or removed
	leftover bool

	// virtual NICs passed so a NAT guest can be forwarded into the tun
	vmIfaces []string
	// non-nil while the anchor is loaded and the list is being refreshed.
	vmStop chan struct{}
}

func New() (firewall.Firewall, error) {
	useInstanceNames()
	return &DarwinFirewall{v6Available: nettest.SupportsIPv6(), leftover: anchorHasRules()}, nil
}

func (f *DarwinFirewall) HasLeftoverRules() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leftover
}

// Release keeps the anchor and pf enabled. ensurePF already saved the reference, so
// whichever process later takes the rules over or removes them drops it.
func (f *DarwinFirewall) Release(bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopVMWatchLocked()
	f.pfToken = ""
	return nil
}

func anchorHasRules() bool {
	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-sr").CombinedOutput()
	return err == nil && strings.Contains(string(out), "block")
}

func appendPFToken(token string) error {
	fh, err := os.OpenFile(pfTokenFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fmt.Fprintln(fh, token)
	return err
}

// releaseSavedPFTokens drops every saved reference except keep, the one this process holds.
// Earlier processes left the others, whether they released or crashed.
func releaseSavedPFTokens(keep string) {
	data, err := os.ReadFile(pfTokenFile)
	if err != nil {
		return
	}
	for _, token := range strings.Fields(string(data)) {
		if token != keep {
			_, _ = exec.Command("pfctl", "-X", token).CombinedOutput()
		}
	}
	_ = os.Remove(pfTokenFile)
	if keep != "" {
		if err := appendPFToken(keep); err != nil {
			log.Error(tag, "save pf token: %v", err)
		}
	}
}

func (f *DarwinFirewall) SetPersist(enabled bool) { f.persistKillSwitch.Store(enabled) }
func (f *DarwinFirewall) IsPersistent() bool      { return f.persistKillSwitch.Load() }
func (f *DarwinFirewall) IsEnabled() bool         { return f.blockedV4.Load() || f.blockedV6.Load() }

func (f *DarwinFirewall) SetTunnelRequirement(v4, v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev4, prev6 := f.tunnelReqV4.Load(), f.tunnelReqV6.Load()
	f.tunnelReqV4.Store(v4)
	f.tunnelReqV6.Store(v6)
	if err := f.reconcileLocked(); err != nil {
		f.tunnelReqV4.Store(prev4)
		f.tunnelReqV6.Store(prev6)
		return err
	}
	return nil
}

func (f *DarwinFirewall) SetIndependentLockdown(enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.persistKillSwitch.Load()
	f.persistKillSwitch.Store(enabled)
	if err := f.reconcileLocked(); err != nil {
		f.persistKillSwitch.Store(prev)
		return err
	}
	return nil
}

func (f *DarwinFirewall) AddTunnelBypasses(iface string) error {
	if !f.IsEnabled() {
		return fmt.Errorf("kill switch must be enabled to add tunnel bypasses")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunName = strings.Clone(iface)
	return f.reconcileLocked()
}

func (f *DarwinFirewall) RemoveTunnelBypasses(iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tunName == iface || iface == "" {
		f.tunName = ""
	}
	if !f.IsEnabled() {
		return nil
	}
	return f.reconcileLocked()
}

func (f *DarwinFirewall) SetTunnelPort(port uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listenPort = port
	if !f.IsEnabled() {
		return nil
	}
	return f.reconcileLocked()
}

func (f *DarwinFirewall) UpdatePermittedRoutes(routes []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peerPass = append([]netip.Prefix(nil), routes...)
	if !f.IsEnabled() {
		return nil
	}
	return f.reconcileLocked()
}

func (f *DarwinFirewall) AllowLocalNetworks(prefixes []netip.Prefix) error {
	if !f.IsEnabled() {
		return fmt.Errorf("kill switch must be enabled to allow local networks")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.localNets = append([]netip.Prefix(nil), prefixes...)
	return f.reconcileLocked()
}

func (f *DarwinFirewall) RemoveLocalNetworks() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.localNets = nil
	if !f.IsEnabled() {
		return nil
	}
	return f.reconcileLocked()
}

func (f *DarwinFirewall) IsAllowLocalNetworksEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.localNets) > 0
}

func (f *DarwinFirewall) Disable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev4, prev6 := f.tunnelReqV4.Load(), f.tunnelReqV6.Load()
	prevPersist := f.persistKillSwitch.Load()
	prevTun, prevPort := f.tunName, f.listenPort
	prevLocal, prevPeer := f.localNets, f.peerPass
	f.tunnelReqV4.Store(false)
	f.tunnelReqV6.Store(false)
	f.persistKillSwitch.Store(false)
	f.tunName = ""
	f.listenPort = 0
	f.localNets = nil
	f.peerPass = nil
	if err := f.reconcileLocked(); err != nil {
		f.tunnelReqV4.Store(prev4)
		f.tunnelReqV6.Store(prev6)
		f.persistKillSwitch.Store(prevPersist)
		f.tunName = prevTun
		f.listenPort = prevPort
		f.localNets = prevLocal
		f.peerPass = prevPeer
		return err
	}
	return nil
}

func (f *DarwinFirewall) reconcileLocked() error {
	wantV4, wantV6 := f.anchorFamilies()

	if !wantV4 && !wantV6 {
		f.stopVMWatchLocked()
		f.vmIfaces = nil
		f.unloadAnchor()
		f.blockedV4.Store(false)
		f.blockedV6.Store(false)
		return nil
	}

	freshToken, err := f.ensurePF()
	if err != nil {
		return err
	}
	inserted, err := f.ensureAnchorCall()
	if err != nil {
		if freshToken {
			f.releasePFToken()
		}
		return err
	}
	prevVM := f.vmIfaces
	f.vmIfaces = listVMPassIfaces()
	if err := f.loadAnchor(wantV4, wantV6); err != nil {
		f.vmIfaces = prevVM
		f.abortNewAnchor(freshToken, inserted)
		return err
	}
	// Best effort. A missing legacy anchor is the common case.
	flushAnchor(pfLegacyAnchorName)
	if err := killBlockedPFStates(f.keepLocked()); err != nil {
		f.abortNewAnchor(freshToken, inserted)
		return err
	}
	f.blockedV4.Store(wantV4)
	f.blockedV6.Store(wantV6)
	if f.leftover {
		// The reload replaced the leftover anchor in one step, so their references can go.
		releaseSavedPFTokens(f.pfToken)
		f.leftover = false
	}
	f.startVMWatchLocked()
	log.Debug(tag, "pf kill switch active v4=%v v6=%v tun=%s vm=%v", wantV4, wantV6, f.tunName, f.vmIfaces)
	return nil
}

// ensurePF enables pf with a reference token. fresh is true only when this call took the token.
func (f *DarwinFirewall) ensurePF() (fresh bool, err error) {
	if f.pfToken != "" {
		return false, nil
	}
	out, err := exec.Command("pfctl", "-E").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already enabled") {
		// -E still prints Token on success; treat "already enabled" as ok
		if !strings.Contains(strings.ToLower(string(out)), "token") {
			return false, fmt.Errorf("pfctl -E: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	f.pfToken = parsePFToken(string(out))
	if f.pfToken == "" {
		return false, fmt.Errorf("pfctl -E returned no token (%s)", cleanPfctlOutput(out))
	}
	// Saved right away, so a later process can drop it even if this one crashes.
	if err := appendPFToken(f.pfToken); err != nil {
		log.Error(tag, "save pf token: %v", err)
	}
	return true, nil
}

// ensureAnchorCall inserts anchor "wgtunnel" into the live main ruleset when it is missing.
// A later pfctl -f /etc/pf.conf drops that call, so the reconcile and the watch loop check again.
func (f *DarwinFirewall) ensureAnchorCall() (inserted bool, err error) {
	present, err := hasPFAnchor(pfAnchorName)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	if err := addPFAnchor(pfAnchorName); err != nil {
		return false, err
	}
	return true, nil
}

// abortNewAnchor drops an anchor this attempt attached. A refresh that did not
// take the token or insert the call leaves the running ruleset in place.
func (f *DarwinFirewall) abortNewAnchor(freshToken, inserted bool) {
	if !freshToken && !inserted {
		return
	}
	flushAnchor(pfAnchorName)
	if inserted {
		if err := removePFAnchor(pfAnchorName); err != nil {
			log.Error(tag, "roll back pf anchor: %v", err)
		}
	}
	if freshToken {
		f.releasePFToken()
	}
}

func parsePFToken(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token :") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Token :"))
		}
		if strings.HasPrefix(line, "Token:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
		}
	}
	return ""
}

func (f *DarwinFirewall) loadAnchor(wantV4, wantV6 bool) error {
	rules := f.buildRules(wantV4, wantV6)
	// stdin rather than a file: nothing is left on disk to go stale between runs
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// pfctl reports syntax errors as <file>:<line>: ... so the numbered ruleset is what
		// makes the failure actionable
		log.Error(tag, "pf anchor %s rejected ruleset:\n%s", pfAnchorName, numberLines(rules))
		return fmt.Errorf("pfctl -a %s -f -: %v (%s)", pfAnchorName, err, cleanPfctlOutput(out))
	}
	return nil
}

// unloadAnchor always flushes the anchor body, so a failed remove of the call
// leaves an empty anchor in the main ruleset and no block rules.
func (f *DarwinFirewall) unloadAnchor() {
	if err := removePFAnchor(pfAnchorName); err != nil {
		log.Error(tag, "remove pf anchor call: %v", err)
	}
	flushAnchor(pfAnchorName)
	flushAnchor(pfLegacyAnchorName)
	f.releasePFToken()
	releaseSavedPFTokens("")
	f.leftover = false
}

func flushAnchor(name string) {
	_, _ = exec.Command("pfctl", "-a", name, "-F", "all").CombinedOutput()
}

func (f *DarwinFirewall) releasePFToken() {
	if f.pfToken == "" {
		return
	}
	_, _ = exec.Command("pfctl", "-X", f.pfToken).CombinedOutput()
	f.pfToken = ""
}

// cleanPfctlOutput drops the lines Apple's pfctl prints on every invocation regardless of
// outcome
func cleanPfctlOutput(out []byte) string {
	var kept []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "",
			strings.Contains(line, "ALTQ"),
			strings.Contains(line, "Use of -f option"),
			strings.Contains(line, "present in the main ruleset"),
			strings.Contains(line, "See /etc/pf.conf"):
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "; ")
}

func numberLines(s string) string {
	var b strings.Builder
	for i, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		fmt.Fprintf(&b, "%3d  %s\n", i+1, line)
	}
	return b.String()
}

func (f *DarwinFirewall) buildRules(wantV4, wantV6 bool) string {
	var b strings.Builder
	b.WriteString("# wgtunnel kill-switch anchor (ephemeral)\n")

	pass := f.passTable()
	if len(pass) > 0 {
		b.WriteString("table <wgtunnel_pass> persist { ")
		b.WriteString(strings.Join(pass, ", "))
		b.WriteString(" }\n")
	} else {
		b.WriteString("table <wgtunnel_pass> persist\n")
	}

	// flags any picks up TCP mid-stream. With the default S/SA, a connection
	// opened while pf was off has no state and gets dropped.
	b.WriteString("pass quick on lo0 all flags any\n")
	if f.tunName != "" && safeIface(f.tunName) {
		fmt.Fprintf(&b, "pass quick on %s all flags any\n", f.tunName)
	}
	// A NAT guest arrives on a virtual NIC. Passing it lets the host forward
	// the packet into the tun. if-bound keeps the state on that NIC, so the
	// forwarded packet can't ride it out the physical NIC past the block below.
	// Bridges that aren't virtual are not in this list.
	for _, name := range f.vmIfaces {
		if name == f.tunName || !safeIface(name) {
			continue
		}
		fmt.Fprintf(&b, "pass quick on %s all flags any keep state (if-bound)\n", name)
	}

	// Bootstrap sockets are marked via IP_TOS/IPV6_TCLASS. Any process can set
	// that mark, so it only counts from root, which the daemon runs as.
	fmt.Fprintf(&b, "pass out quick proto { tcp udp } all tos 0x%02x user root flags any\n", mark.DarwinBootstrapTOS)

	b.WriteString("pass out quick proto udp from port 68 to port 67\n")
	b.WriteString("pass in quick proto udp from port 67 to port 68\n")

	if wantV6 {
		// NDP: router solicit/advert, neighbor solicit/advert, redirect (RFC 4861 types
		// 133-137). Numeric so there's no pf keyword spelling to get wrong - an unknown name is
		// a syntax error that rejects the whole anchor and leaves no kill switch at all.
		b.WriteString("pass quick inet6 proto 58 icmp6-type { 133, 134, 135, 136, 137 }\n")
	}
	if f.listenPort != 0 {
		fmt.Fprintf(&b, "pass in quick proto udp to port %d\n", f.listenPort)
		fmt.Fprintf(&b, "pass out quick proto udp from port %d\n", f.listenPort)
	}
	if len(pass) > 0 {
		b.WriteString("pass in quick from <wgtunnel_pass> to any flags any\n")
		b.WriteString("pass out quick from any to <wgtunnel_pass> flags any\n")
	}
	// Outbound return is quick, so it wins over the drop below it. Inbound does
	// not match "out" and falls through to the drop.
	if wantV4 {
		b.WriteString("block return out quick inet all\n")
		b.WriteString("block drop quick inet all\n")
	}
	if wantV6 {
		b.WriteString("block return out quick inet6 all\n")
		b.WriteString("block drop quick inet6 all\n")
	}
	return b.String()
}

// keepLocked describes the traffic the anchor passes, for the state kill.
func (f *DarwinFirewall) keepLocked() pfKeep {
	k := pfKeep{tun: f.tunName, listenPort: f.listenPort, vmIfaces: f.vmIfaces}
	k.pass = append(k.pass, f.localNets...)
	k.pass = append(k.pass, f.peerPass...)
	if f.tunName != "" {
		k.tunNets = ifacePrefixes(f.tunName)
	}
	return k
}

func ifacePrefixes(name string) []netip.Prefix {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(ipn.String())
		if err != nil {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}

func (f *DarwinFirewall) passTable() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p netip.Prefix) {
		if !p.IsValid() {
			return
		}
		s := p.Masked().String()
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, p := range f.localNets {
		add(p)
	}
	for _, p := range f.peerPass {
		add(p)
	}
	return out
}
