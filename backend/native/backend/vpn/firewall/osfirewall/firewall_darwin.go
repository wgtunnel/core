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
	"os"
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
	tag          = "Firewall"
	pfAnchorName = "com.wgtunnel"
	pfAnchorFile = "/var/run/wgtunnel.pf"
	stockPFConf  = "/etc/pf.conf"
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

	pfToken        string
	combinedLoaded bool
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

func (f *DarwinFirewall) ensureAnchorRef() error {
	sr, _ := exec.Command("pfctl", "-sr").CombinedOutput()
	if strings.Contains(string(sr), `anchor "`+pfAnchorName+`"`) {
		return nil
	}

	// pfAnchorFile must exist before pfctl runs as it loads it immediately
	if _, err := os.Stat(pfAnchorFile); os.IsNotExist(err) {
		if err := os.WriteFile(pfAnchorFile, []byte{}, 0o600); err != nil {
			return fmt.Errorf("create placeholder %s: %w", pfAnchorFile, err)
		}
	}
	stock, err := os.ReadFile(stockPFConf)
	if err != nil {
		stock = []byte{}
	}
	combined := string(stock)
	if combined != "" && !strings.HasSuffix(combined, "\n") {
		combined += "\n"
	}
	combined += fmt.Sprintf("anchor \"%s\"\nload anchor \"%s\" from \"%s\"\n", pfAnchorName, pfAnchorName, pfAnchorFile)
	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(combined)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl load combined ruleset: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	f.combinedLoaded = true
	return nil
}

func (f *DarwinFirewall) loadAnchor(wantV4, wantV6 bool) error {
	rules := f.buildRules(wantV4, wantV6)
	if err := os.WriteFile(pfAnchorFile, []byte(rules), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", pfAnchorFile, err)
	}
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f *DarwinFirewall) unloadAnchor() error {
	_, _ = exec.Command("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput()
	_ = os.Remove(pfAnchorFile)
	if f.combinedLoaded {
		if _, err := os.Stat(stockPFConf); err == nil {
			cmd := exec.Command("pfctl", "-f", stockPFConf)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Error(tag, "restore %s: %v (%s)", stockPFConf, err, strings.TrimSpace(string(out)))
			}
		}
		f.combinedLoaded = false
	}
	if f.pfToken != "" {
		_, _ = exec.Command("pfctl", "-X", f.pfToken).CombinedOutput()
		f.pfToken = ""
	}
	return nil
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
	fmt.Fprintf(&b, "pass out quick tos 0x%02x all\n", mark.DarwinBootstrapTOS)

	b.WriteString("pass out quick proto udp from port 68 to port 67\n")
	b.WriteString("pass in quick proto udp from port 67 to port 68\n")
	b.WriteString("pass quick inet proto icmp all\n")
	if wantV6 {
		b.WriteString("pass quick inet6 proto ipv6-icmp all\n")
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
