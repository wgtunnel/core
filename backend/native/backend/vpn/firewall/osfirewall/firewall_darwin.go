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
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/mark"
	"golang.org/x/net/nettest"
)

const (
	tag = "Firewall"
	// Sub-anchor to not replace main ruleset
	pfAnchorName = "com.apple/wgtunnel"
	pfMainAnchor = `anchor "com.apple/*"`
)

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
}

func New() (firewall.Firewall, error) {
	return &DarwinFirewall{v6Available: nettest.SupportsIPv6()}, nil
}

func (f *DarwinFirewall) SetPersist(enabled bool) { f.persistKillSwitch.Store(enabled) }
func (f *DarwinFirewall) IsPersistent() bool      { return f.persistKillSwitch.Load() }
func (f *DarwinFirewall) IsEnabled() bool         { return f.blockedV4.Load() || f.blockedV6.Load() }

func (f *DarwinFirewall) SetTunnelRequirement(v4, v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnelReqV4.Store(v4)
	f.tunnelReqV6.Store(v6)
	return f.reconcileLocked()
}

func (f *DarwinFirewall) SetIndependentLockdown(enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.persistKillSwitch.Store(enabled)
	return f.reconcileLocked()
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
	f.tunnelReqV4.Store(false)
	f.tunnelReqV6.Store(false)
	f.persistKillSwitch.Store(false)
	f.tunName = ""
	f.listenPort = 0
	f.localNets = nil
	f.peerPass = nil
	return f.reconcileLocked()
}

func (f *DarwinFirewall) reconcileLocked() error {
	persist := f.persistKillSwitch.Load()
	wantV4 := f.tunnelReqV4.Load() || persist
	wantV6 := (f.tunnelReqV6.Load() || persist) && f.v6Available

	if !wantV4 && !wantV6 {
		if err := f.unloadAnchor(); err != nil {
			log.Error(tag, "unload pf anchor: %v", err)
		}
		f.blockedV4.Store(false)
		f.blockedV6.Store(false)
		return nil
	}

	if err := f.ensurePF(); err != nil {
		return err
	}
	if err := f.loadAnchor(wantV4, wantV6); err != nil {
		return err
	}
	f.blockedV4.Store(wantV4)
	f.blockedV6.Store(wantV6)
	log.Debug(tag, "pf kill switch active v4=%v v6=%v tun=%s", wantV4, wantV6, f.tunName)
	return nil
}

func (f *DarwinFirewall) ensurePF() error {
	if f.pfToken == "" {
		out, err := exec.Command("pfctl", "-E").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already enabled") {
			// -E still prints Token on success; treat "already enabled" as ok
			if !strings.Contains(strings.ToLower(string(out)), "token") {
				return fmt.Errorf("pfctl -E: %v (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		f.pfToken = parsePFToken(string(out))
	}
	return f.ensureAnchorRef()
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

// ensureAnchorRef verifies our anchor will actually be evaluated
func (f *DarwinFirewall) ensureAnchorRef() error {
	out, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -sr: %v (%s)", err, cleanPfctlOutput(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		// HasPrefix on purpose: "scrub-anchor" lines also contain the substring
		if strings.HasPrefix(strings.TrimSpace(line), pfMainAnchor) {
			return nil
		}
	}
	return fmt.Errorf(
		"main pf ruleset has no %s, so anchor %q would never be evaluated; "+
			"restore the stock /etc/pf.conf (sudo pfctl -f /etc/pf.conf)",
		pfMainAnchor, pfAnchorName,
	)
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

func (f *DarwinFirewall) unloadAnchor() error {
	_, _ = exec.Command("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput()
	if f.pfToken != "" {
		_, _ = exec.Command("pfctl", "-X", f.pfToken).CombinedOutput()
		f.pfToken = ""
	}
	return nil
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

	b.WriteString("pass quick on lo0 all\n")
	if f.tunName != "" && safeIface(f.tunName) {
		fmt.Fprintf(&b, "pass quick on %s all\n", f.tunName)
	}

	// For tunnel boostrap socket bypass via IP_TOS/IPV6_TCLASS
	fmt.Fprintf(&b, "pass out quick all tos 0x%02x\n", mark.DarwinBootstrapTOS)

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
		b.WriteString("pass in quick from <wgtunnel_pass> to any\n")
		b.WriteString("pass out quick from any to <wgtunnel_pass>\n")
	}
	if wantV4 {
		b.WriteString("block drop inet all\n")
	}
	if wantV6 {
		b.WriteString("block drop inet6 all\n")
	}
	return b.String()
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

func safeIface(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
