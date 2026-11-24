// Copyright (c) 2026 Zane Schepke / WG Tunnel
//
// Portions of this file are derived from Tailscale
// Copyright (c) Tailscale Inc & contributors
// Licensed under the BSD 3-Clause License
// See NOTICE and LICENSES/BSD-3-Clause.txt in the project root

//go:build windows

package osfirewall

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wf"
	"github.com/wgtunnel/backend/instance"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/windows"
)

const tag = "Firewall"

type WindowsFirewall struct {
	mu sync.Mutex

	session *wf.Session

	providerID wf.ProviderID
	sublayerID wf.SublayerID

	iface string

	luid           uint64
	appID          string
	baseRulesAdded atomic.Bool

	tunnelReqV4 atomic.Bool
	tunnelReqV6 atomic.Bool
	persistReq  atomic.Bool

	persistKillSwitch atomic.Bool

	blockedV4    atomic.Bool
	blockedV6    atomic.Bool
	blockRulesV4 []*wf.Rule
	blockRulesV6 []*wf.Rule

	tunRules        []*wf.Rule
	localAddrRules  []*wf.Rule
	permittedRoutes map[netip.Prefix][]*wf.Rule

	// rules an earlier process left in our sublayer, until taken over or removed
	leftover []wf.RuleID
	// every rule this process added and hasn't deleted, so Release can re-add them as
	// persistent
	added map[wf.RuleID]*wf.Rule
}

// Fixed IDs so a later process can find what an earlier one left. The session is not
// dynamic, so its objects outlive the process. They are not persistent, so a reboot
// drops them, like pf and nftables rules. These are release's; other instances use wfpIDs.
var (
	wgtProviderID = wf.ProviderID(windows.GUID{
		Data1: 0x7767746e, Data2: 0x6e75, Data3: 0x4b53,
		Data4: [8]byte{0x80, 0x01, 0x77, 0x67, 0x74, 0x75, 0x6e, 0x01},
	})
	wgtSublayerID = wf.SublayerID(windows.GUID{
		Data1: 0x7767746e, Data2: 0x6e75, Data3: 0x4b53,
		Data4: [8]byte{0x80, 0x02, 0x77, 0x67, 0x74, 0x75, 0x6e, 0x02},
	})
)

// wfpIDs are the provider and sublayer of this instance. Release keeps the IDs it always had,
// any other instance gets its own, the same on every run, so its rules never mix with
// release's.
func wfpIDs() (wf.ProviderID, wf.SublayerID) {
	if instance.IsDefault() {
		return wgtProviderID, wgtSublayerID
	}
	n := instance.Name()
	return wf.ProviderID(nameGUID("wfp-provider/" + n)), wf.SublayerID(nameGUID("wfp-sublayer/" + n))
}

// nameGUID is a version 5 style GUID (SHA-256 truncated) for name.
func nameGUID(name string) windows.GUID {
	sum := sha256.Sum256([]byte("wgtunnel/" + name))
	g := windows.GUID{
		Data1: binary.BigEndian.Uint32(sum[0:4]),
		Data2: binary.BigEndian.Uint16(sum[4:6]),
		Data3: binary.BigEndian.Uint16(sum[6:8])&0x0fff | 0x5000,
	}
	copy(g.Data4[:], sum[8:16])
	g.Data4[0] = g.Data4[0]&0x3f | 0x80
	return g
}

func (f *WindowsFirewall) SetPersist(enabled bool) {
	f.persistKillSwitch.Store(enabled)
}

func (f *WindowsFirewall) IsPersistent() bool {
	return f.persistKillSwitch.Load()
}

type weight uint64

const (
	weightDaemonTraffic weight = 15
	weightKnownTraffic  weight = 12
	weightCatchAll      weight = 0
)

type protocol int

const (
	protocolV4 protocol = iota
	protocolV6
	protocolAll
)

type direction int

const (
	directionInbound direction = iota
	directionOutbound
	directionBoth
)

// Known addresses.
var (
	linkLocalRange           = netip.MustParsePrefix("fe80::/10")
	linkLocalDHCPMulticast   = netip.MustParseAddr("ff02::1:2")
	siteLocalDHCPMulticast   = netip.MustParseAddr("ff05::1:3")
	linkLocalRouterMulticast = netip.MustParseAddr("ff02::2")
)

func New() (firewall.Firewall, error) {
	f := &WindowsFirewall{
		permittedRoutes: make(map[netip.Prefix][]*wf.Rule),
		tunRules:        make([]*wf.Rule, 0),
		added:           make(map[wf.RuleID]*wf.Rule),
	}

	if err := f.createSession(); err != nil {
		return nil, err
	}
	rules, err := f.ourRules()
	if err != nil {
		log.Error(tag, "list leftover WFP rules: %v", err)
	}
	for _, r := range rules {
		f.leftover = append(f.leftover, r.ID)
	}

	// try to cache the app id once to prevent https://github.com/tailscale/wf/issues/25
	if err := f.cacheAppID(); err != nil {
		log.Error(tag, "failed to cache daemon AppID: %v", err)
	}

	return f, nil
}

func (f *WindowsFirewall) AllowLocalNetworks(addrs []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// cleanup old local addr rules
	f.RemoveLocalNetworks()

	// add new rules
	addedByPrefix, err := f.addPermissiveRulesForPrefixes(addrs, "bypass for local addr ")
	if err != nil {
		return err
	}
	f.localAddrRules = nil
	for _, rules := range addedByPrefix {
		f.localAddrRules = append(f.localAddrRules, rules...)
	}
	log.Debug(tag, "Bypassed local addrs in firewall")
	return nil
}

func (f *WindowsFirewall) RemoveLocalNetworks() error {
	if err := f.removeRules(f.localAddrRules); err != nil {
		log.Error(tag, "Failed to remove old local addr rules: %v", err)
	}
	f.localAddrRules = nil

	return nil
}

func (f *WindowsFirewall) IsAllowLocalNetworksEnabled() bool {
	return f.localAddrRules != nil
}

func (f *WindowsFirewall) UpdatePermittedRoutes(newRoutes []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// routes to remove
	var routesToRemove []netip.Prefix
	for existing := range f.permittedRoutes {
		found := false
		for _, newRoute := range newRoutes {
			if existing == newRoute {
				found = true
				break
			}
		}
		if !found {
			routesToRemove = append(routesToRemove, existing)
		}
	}
	for _, r := range routesToRemove {
		rules := f.permittedRoutes[r]
		if err := f.removeRules(rules); err != nil {
			log.Error(tag, "Failed to remove permitted route %v: %v", r, err)
		}
		delete(f.permittedRoutes, r)
	}

	// routes to add
	var routesToAdd []netip.Prefix
	for _, newRoute := range newRoutes {
		if _, exists := f.permittedRoutes[newRoute]; !exists {
			routesToAdd = append(routesToAdd, newRoute)
		}
	}

	// add new rules
	addedByPrefix, err := f.addPermissiveRulesForPrefixes(routesToAdd, "permitted route - ")
	if err != nil {
		return err
	}
	for prefix, rules := range addedByPrefix {
		f.permittedRoutes[prefix] = rules
	}

	log.Debug(tag, "Updated permitted routes: %v", newRoutes)
	return nil
}

func (f *WindowsFirewall) BypassTunnel(luid uint64, listenPort uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.luid = luid
	if err := f.permitTunInterface(weightDaemonTraffic); err != nil {
		return fmt.Errorf("permitTunInterface failed: %w", err)
	}
	log.Debug(tag, "Bypassing listen port %d", listenPort)
	if err := f.permitListenPort(weightDaemonTraffic, listenPort); err != nil {
		return fmt.Errorf("permitListenPort failed: %w", err)
	}
	log.Debug(tag, "Tunnel successfully bypassed")
	return nil
}

// reconcile brings actual firewall enforcement in line with the active tunnel and kill switch requirements
func (f *WindowsFirewall) reconcile() error {
	persist := f.persistKillSwitch.Load()
	wantV4 := f.tunnelReqV4.Load() || persist
	wantV6 := f.tunnelReqV6.Load() || persist

	if !wantV4 && !wantV6 {
		if f.blockedV4.Load() {
			if err := f.removeRules(f.blockRulesV4); err != nil {
				log.Error(tag, "Failed to remove v4 block rules: %v", err)
			}
			f.blockRulesV4 = nil
			f.blockedV4.Store(false)
		}
		if f.blockedV6.Load() {
			if err := f.removeRules(f.blockRulesV6); err != nil {
				log.Error(tag, "Failed to remove v6 block rules: %v", err)
			}
			f.blockRulesV6 = nil
			f.blockedV6.Store(false)
		}
		return nil
	}

	if err := f.ensureSession(); err != nil {
		return fmt.Errorf("ensure WFP session: %w", err)
	}

	if !f.baseRulesAdded.Load() {
		if err := f.permitDaemon(weightDaemonTraffic); err != nil {
			return fmt.Errorf("permitDaemon failed: %w", err)
		}
		if err := f.permitLoopback(weightDaemonTraffic); err != nil {
			return fmt.Errorf("permitLoopback failed: %w", err)
		}
		if err := f.permitDHCPv4(weightKnownTraffic); err != nil {
			return fmt.Errorf("permitDHCPv4 failed: %w", err)
		}

		if nettest.SupportsIPv6() {
			if err := f.permitDHCPv6(weightKnownTraffic); err != nil {
				return fmt.Errorf("permitDHCPv6 failed: %w", err)
			}

			if err := f.permitNDP(weightKnownTraffic); err != nil {
				return fmt.Errorf("permitNDP failed: %w", err)
			}
		}

		f.baseRulesAdded.Store(true)
	}

	if wantV4 && !f.blockedV4.Load() {
		rules, err := f.addRules("all", weightCatchAll, nil, wf.ActionBlock, protocolV4, directionBoth)
		if err != nil {
			return fmt.Errorf("blockAll v4 failed: %w", err)
		}
		f.blockRulesV4 = rules
		f.blockedV4.Store(true)
	} else if !wantV4 && f.blockedV4.Load() {
		if err := f.removeRules(f.blockRulesV4); err != nil {
			log.Error(tag, "Failed to remove v4 block rules: %v", err)
		}
		f.blockRulesV4 = nil
		f.blockedV4.Store(false)
	}

	if wantV6 && !f.blockedV6.Load() {
		rules, err := f.addRules("all", weightCatchAll, nil, wf.ActionBlock, protocolV6, directionBoth)
		if err != nil {
			return fmt.Errorf("blockAll v6 failed: %w", err)
		}
		f.blockRulesV6 = rules
		f.blockedV6.Store(true)
	} else if !wantV6 && f.blockedV6.Load() {
		if err := f.removeRules(f.blockRulesV6); err != nil {
			log.Error(tag, "Failed to remove v6 block rules: %v", err)
		}
		f.blockRulesV6 = nil
		f.blockedV6.Store(false)
	}

	// This process's rules are in place now, so the earlier ones can go without a gap.
	f.dropLeftover()
	return nil
}

func (f *WindowsFirewall) dropLeftover() {
	for _, id := range f.leftover {
		if err := f.session.DeleteRule(id); err != nil {
			log.Error(tag, "Failed to delete leftover rule: %v", err)
		}
	}
	if len(f.leftover) > 0 {
		log.Debug(tag, "Took over %d WFP rules left by a previous run", len(f.leftover))
	}
	f.leftover = nil
}

// SetTunnelRequirement declares what the active tunnel's own config currently needs.
func (f *WindowsFirewall) SetTunnelRequirement(v4, v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnelReqV4.Store(v4)
	f.tunnelReqV6.Store(v6)
	return f.reconcile()
}

// SetIndependentLockdown turns the manual kill switch on/off. Turning it off releases a
// family only if the active tunnel doesn't also require it.
func (f *WindowsFirewall) SetIndependentLockdown(enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.persistKillSwitch.Store(enabled)
	return f.reconcile()
}

func (f *WindowsFirewall) IsEnabled() bool {
	return f.blockedV4.Load() || f.blockedV6.Load()
}

func (f *WindowsFirewall) cacheAppID() error {
	currentFile, err := os.Executable()
	if err != nil {
		return err
	}

	appID, err := wf.AppID(currentFile)
	if err != nil {
		return fmt.Errorf("could not get app id for %q: %w", currentFile, err)
	}

	f.appID = appID
	log.Debug(tag, "Cached daemon AppID: %s (will never call wf.AppID again)", appID)
	return nil
}

func (f *WindowsFirewall) RemoveTunnelRules() error {
	tunRulesCopy := make([]*wf.Rule, len(f.tunRules))
	copy(tunRulesCopy, f.tunRules)
	f.tunRules = nil
	if err := f.removeRules(tunRulesCopy); err != nil {
		log.Error(tag, "Failed to remove tun rules: %v", err)
	}

	permittedCopy := make(map[netip.Prefix][]*wf.Rule, len(f.permittedRoutes))
	for k, v := range f.permittedRoutes {
		permittedCopy[k] = v
	}
	f.permittedRoutes = make(map[netip.Prefix][]*wf.Rule)

	for prefix, rules := range permittedCopy {
		if err := f.removeRules(rules); err != nil {
			log.Error(tag, "Failed to remove permitted route %s: %v", prefix, err)
		}
	}

	log.Debug(tag, "Tunnel rules and permitted routes removed")
	return nil
}

// permitDNS allows outbound DNS queries on UDP/TCP port 53 for bootstrapping tunnels.
func (f *WindowsFirewall) permitDNS(w weight) error {
	conditions := []*wf.Match{
		{
			Field: wf.FieldALEAppID,
			Op:    wf.MatchTypeEqual,
			Value: f.appID,
		},
	}

	// UDP DNS
	udpConditions := append([]*wf.Match{}, conditions...)
	udpConditions = append(udpConditions, &wf.Match{
		Field: wf.FieldIPProtocol,
		Op:    wf.MatchTypeEqual,
		Value: wf.IPProtoUDP,
	}, &wf.Match{
		Field: wf.FieldIPRemotePort,
		Op:    wf.MatchTypeEqual,
		Value: uint16(53),
	})
	_, err := f.addRules("DNS UDP", w, udpConditions, wf.ActionPermit, protocolAll, directionOutbound)
	if err != nil {
		return err
	}

	// TCP DNS
	tcpConditions := append([]*wf.Match{}, conditions...)
	tcpConditions = append(tcpConditions, &wf.Match{
		Field: wf.FieldIPProtocol,
		Op:    wf.MatchTypeEqual,
		Value: wf.IPProtoTCP,
	}, &wf.Match{
		Field: wf.FieldIPRemotePort,
		Op:    wf.MatchTypeEqual,
		Value: uint16(53),
	})
	_, err = f.addRules("DNS TCP", w, tcpConditions, wf.ActionPermit, protocolAll, directionOutbound)
	return err
}

// addPermissiveRulesForPrefixes is a helper to add permissive rules for a list of prefixes
func (f *WindowsFirewall) addPermissiveRulesForPrefixes(prefixes []netip.Prefix, namePrefix string) (map[netip.Prefix][]*wf.Rule, error) {

	addedByPrefix := make(map[netip.Prefix][]*wf.Rule)
	var partialAdds []netip.Prefix // rollback tracking
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() && !nettest.SupportsIPv6() {
			continue
		}
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: prefix,
			},
		}
		var p protocol
		if prefix.Addr().Is4() {
			p = protocolV4
		} else {
			p = protocolV6
		}
		rules, err := f.addRules(namePrefix+prefix.String(), weightKnownTraffic, conditions, wf.ActionPermit, p, directionBoth)
		if err != nil {
			for _, addedPrefix := range partialAdds {
				if delErr := f.removeRules(addedByPrefix[addedPrefix]); delErr != nil {
					log.Error(tag, "Failed to delete partial rules for %v during rollback: %v", addedPrefix, delErr)
				}
			}
			return nil, fmt.Errorf("add permissive rules for %v: %w", prefix, err)
		}
		addedByPrefix[prefix] = rules
		partialAdds = append(partialAdds, prefix)
	}
	return addedByPrefix, nil
}

// removeRules is a helper to remove a list of rules
func (f *WindowsFirewall) removeRules(rules []*wf.Rule) error {

	for _, rule := range rules {
		if err := f.session.DeleteRule(rule.ID); err != nil {
			log.Error(tag, "Failed to delete rule %s: %v", rule.Name, err)
			// Continue to try deleting others
		}
		delete(f.added, rule.ID)
	}
	return nil
}

func (f *WindowsFirewall) Disable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ensureSession(); err != nil {
		return fmt.Errorf("ensure WFP session: %w", err)
	}
	// Everything in our sublayer, including rules an earlier process left. The session
	// isn't dynamic, so closing it would leave them enforced.
	rules, err := f.ourRules()
	if err != nil {
		return fmt.Errorf("list WFP rules: %w", err)
	}
	for _, r := range rules {
		if err := f.session.DeleteRule(r.ID); err != nil {
			log.Error(tag, "Failed to delete rule %s: %v", r.Name, err)
		}
	}
	if err := f.session.DeleteSublayer(f.sublayerID); err != nil {
		log.Error(tag, "Failed to delete WFP sublayer: %v", err)
	}
	if err := f.session.DeleteProvider(f.providerID); err != nil {
		log.Error(tag, "Failed to delete WFP provider: %v", err)
	}
	if err := f.session.Close(); err != nil {
		log.Error(tag, "Failed to close WFP session: %v", err)
	}
	f.session = nil

	f.tunRules = nil
	f.permittedRoutes = make(map[netip.Prefix][]*wf.Rule)
	f.localAddrRules = nil
	f.leftover = nil
	f.added = make(map[wf.RuleID]*wf.Rule)
	f.blockedV4.Store(false)
	f.blockedV6.Store(false)
	f.blockRulesV4 = nil
	f.blockRulesV6 = nil
	f.baseRulesAdded.Store(false)
	f.tunnelReqV4.Store(false)
	f.tunnelReqV6.Store(false)
	f.persistKillSwitch.Store(false)
	log.Debug(tag, "Firewall fully disabled")
	return nil
}

func (f *WindowsFirewall) permitDaemon(w weight) error {
	return f.addDaemonRule()
}

// addDaemonRule add the daemon bypass using the cached AppID
func (f *WindowsFirewall) addDaemonRule() error {
	if f.appID == "" {
		return fmt.Errorf("AppID not cached")
	}

	log.Debug(tag, "Adding bypass rule for daemon (using cached AppID)")

	conditions := []*wf.Match{{
		Field: wf.FieldALEAppID,
		Op:    wf.MatchTypeEqual,
		Value: f.appID,
	}}

	_, err := f.addRules("unrestricted traffic for daemon", weightDaemonTraffic,
		conditions, wf.ActionPermit, protocolAll, directionBoth)
	return err
}

// createSession opens a session and makes sure our provider and sublayer exist. An
// earlier process may have left both.
func (f *WindowsFirewall) createSession() error {
	session, err := wf.New(&wf.Options{
		Name:        "WG Tunnel firewall",
		Description: "Manages WG Tunnel firewall rules",
	})
	if err != nil {
		return fmt.Errorf("create WFP session: %w", err)
	}
	f.session = session
	f.providerID, f.sublayerID = wfpIDs()

	providers, err := session.Providers()
	if err != nil {
		return fmt.Errorf("list WFP providers: %w", err)
	}
	if !slices.ContainsFunc(providers, func(p *wf.Provider) bool { return p.ID == f.providerID }) {
		// Persistent so persistent filters can reference it. Without filters it has no
		// effect, and Disable deletes it.
		if err := session.AddProvider(&wf.Provider{
			ID:         f.providerID,
			Name:       "WG Tunnel provider",
			Persistent: true,
		}); err != nil {
			return err
		}
	}

	sublayers, err := session.Sublayers(f.providerID)
	if err != nil {
		return fmt.Errorf("list WFP sublayers: %w", err)
	}
	// Weight is this sublayer's priority relative to other sublayers on the system,
	// unrelated to the filter weight constants above, which only order rules within this
	// sublayer. We max it out so nothing else on the system can prioritize over our rules.
	if !slices.ContainsFunc(sublayers, func(sl *wf.Sublayer) bool { return sl.ID == f.sublayerID }) {
		if err := session.AddSublayer(&wf.Sublayer{
			ID:         f.sublayerID,
			Name:       "WG Tunnel permissive and blocking filters",
			Provider:   f.providerID,
			Weight:     math.MaxUint16,
			Persistent: true,
		}); err != nil {
			return err
		}
	}

	log.Debug(tag, "Opened WFP session")
	return nil
}

// ourRules lists every rule in our sublayer, whichever process added it.
func (f *WindowsFirewall) ourRules() ([]*wf.Rule, error) {
	all, err := f.session.Rules()
	if err != nil {
		return nil, err
	}
	var out []*wf.Rule
	for _, r := range all {
		if r.Sublayer == f.sublayerID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *WindowsFirewall) HasLeftoverRules() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.leftover) > 0
}

// Release closes the session. The session isn't dynamic, so the rules stay enforced.
// With acrossReboot they are re-added as persistent filters first, which Windows enforces
// at the next boot before the service starts.
func (f *WindowsFirewall) Release(acrossReboot bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.session == nil {
		return nil
	}
	if acrossReboot {
		f.persistLocked()
	}
	err := f.session.Close()
	f.session = nil
	return err
}

// persistLocked swaps each rule for a persistent copy, adding the copy before deleting the
// original so nothing is unblocked in between. A rule that can't be copied still blocks
// until reboot.
func (f *WindowsFirewall) persistLocked() {
	copied := 0
	for id, r := range f.added {
		if r.Persistent {
			continue
		}
		guid, err := windows.GenerateGUID()
		if err != nil {
			log.Error(tag, "persist rule %s: %v", r.Name, err)
			continue
		}
		c := *r
		c.ID = wf.RuleID(guid)
		c.Persistent = true
		if err := f.session.AddRule(&c); err != nil {
			log.Error(tag, "persist rule %s: %v", r.Name, err)
			continue
		}
		if err := f.session.DeleteRule(id); err != nil {
			log.Error(tag, "delete rule %s after persisting: %v", r.Name, err)
		}
		delete(f.added, id)
		f.added[c.ID] = &c
		copied++
	}
	log.Debug(tag, "Kept %d WFP rules across reboot", copied)
}

// ensureSession reuses the existing session if it's still alive, otherwise creates a new one.
func (f *WindowsFirewall) ensureSession() error {
	if f.session != nil {
		return nil
	}
	return f.createSession()
}

func (f *WindowsFirewall) permitLoopback(w weight) error {

	condition := []*wf.Match{
		{
			Field: wf.FieldFlags,
			Op:    wf.MatchTypeFlagsAllSet,
			Value: wf.ConditionFlagIsLoopback,
		},
	}
	_, err := f.addRules("on loopback", w, condition, wf.ActionPermit, protocolAll, directionBoth)
	return err
}

func (f *WindowsFirewall) permitListenPort(w weight, listenPort uint16) error {

	conditions := []*wf.Match{
		{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: f.luid},
		{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: listenPort},
	}
	rules, err := f.addRules("WireGuard UDP", w, conditions, wf.ActionPermit, protocolAll, directionInbound)
	if err != nil {
		return err
	}
	f.tunRules = append(f.tunRules, rules...)
	return nil
}

func (f *WindowsFirewall) permitDHCPv6(w weight) error {

	var dhcpConditions = func(remoteAddrs ...any) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalAddress,
				Op:    wf.MatchTypeEqual,
				Value: linkLocalRange,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(546),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(547),
			},
		}
		for _, a := range remoteAddrs {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: a,
			})
		}
		return conditions
	}
	conditions := dhcpConditions(linkLocalDHCPMulticast, siteLocalDHCPMulticast)
	if _, err := f.addRules("DHCP request", w, conditions, wf.ActionPermit, protocolV6, directionOutbound); err != nil {
		return err
	}
	conditions = dhcpConditions(linkLocalRange)
	if _, err := f.addRules("DHCP response", w, conditions, wf.ActionPermit, protocolV6, directionInbound); err != nil {
		return err
	}
	return nil
}

func (f *WindowsFirewall) permitDHCPv4(w weight) error {

	var dhcpConditions = func(remoteAddrs ...any) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(68),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(67),
			},
		}
		for _, a := range remoteAddrs {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: a,
			})
		}
		return conditions
	}
	conditions := dhcpConditions(netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	if _, err := f.addRules("DHCP request", w, conditions, wf.ActionPermit, protocolV4, directionOutbound); err != nil {
		return err
	}

	conditions = dhcpConditions()
	if _, err := f.addRules("DHCP response", w, conditions, wf.ActionPermit, protocolV4, directionInbound); err != nil {
		return err
	}
	return nil
}

func (f *WindowsFirewall) permitNDP(w weight) error {

	// These are aliased according to:
	// https://social.msdn.microsoft.com/Forums/azure/en-US/eb2aa3cd-5f1c-4461-af86-61e7d43ccc23/filtering-icmp-by-type-code?forum=wfp
	fieldICMPType := wf.FieldIPLocalPort
	fieldICMPCode := wf.FieldIPRemotePort

	var icmpConditions = func(t, c uint16, remoteAddress any) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoICMPV6,
			},
			{
				Field: fieldICMPType,
				Op:    wf.MatchTypeEqual,
				Value: t,
			},
			{
				Field: fieldICMPCode,
				Op:    wf.MatchTypeEqual,
				Value: c,
			},
		}
		if remoteAddress != nil {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: linkLocalRouterMulticast,
			})
		}
		return conditions
	}
	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	conditions := icmpConditions(133, 0, linkLocalRouterMulticast)
	if _, err := f.addRules("NDP type 133", w, conditions, wf.ActionPermit, protocolV6, directionOutbound); err != nil {
		return err
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	conditions = icmpConditions(134, 0, linkLocalRange)
	if _, err := f.addRules("NDP type 134", w, conditions, wf.ActionPermit, protocolV6, directionInbound); err != nil {
		return err
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	conditions = icmpConditions(135, 0, nil)
	if _, err := f.addRules("NDP type 135", w, conditions, wf.ActionPermit, protocolV6, directionBoth); err != nil {
		return err
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	conditions = icmpConditions(136, 0, nil)
	if _, err := f.addRules("NDP type 136", w, conditions, wf.ActionPermit, protocolV6, directionBoth); err != nil {
		return err
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	conditions = icmpConditions(137, 0, linkLocalRange)
	if _, err := f.addRules("NDP type 137", w, conditions, wf.ActionPermit, protocolV6, directionInbound); err != nil {
		return err
	}
	return nil
}

// addRules adds WFP rules with the given parameters
func (f *WindowsFirewall) addRules(name string, w weight, conditions []*wf.Match, action wf.Action, p protocol, d direction) ([]*wf.Rule, error) {
	var rules []*wf.Rule
	for _, layer := range p.getLayers(d) {
		r, err := f.newRule(name, w, layer, conditions, action)
		if err != nil {
			return nil, err
		}
		if err := f.session.AddRule(r); err != nil {
			return nil, err
		}
		f.added[r.ID] = r
		rules = append(rules, r)
	}
	return rules, nil
}

// getLayers returns the wf.LayerIDs where the rules should be added based on the protocol and direction.
func (p protocol) getLayers(d direction) []wf.LayerID {
	var layers []wf.LayerID
	if p == protocolAll || p == protocolV4 {
		if d == directionBoth || d == directionInbound {
			layers = append(layers, wf.LayerALEAuthRecvAcceptV4)
		}
		if d == directionBoth || d == directionOutbound {
			layers = append(layers, wf.LayerALEAuthConnectV4)
		}
	}
	if p == protocolAll || p == protocolV6 {
		if d == directionBoth || d == directionInbound {
			layers = append(layers, wf.LayerALEAuthRecvAcceptV6)
		}
		if d == directionBoth || d == directionOutbound {
			layers = append(layers, wf.LayerALEAuthConnectV6)
		}
	}
	return layers
}

func (f *WindowsFirewall) newRule(name string, w weight, layer wf.LayerID, conditions []*wf.Match, action wf.Action) (*wf.Rule, error) {
	id, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	return &wf.Rule{
		Name:       "WGTunnel-" + ruleName(action, layer, name),
		ID:         wf.RuleID(id),
		Provider:   f.providerID,
		Sublayer:   f.sublayerID,
		Layer:      layer,
		Weight:     uint64(w),
		Conditions: conditions,
		Action:     action,
	}, nil
}

func ruleName(action wf.Action, layerID wf.LayerID, name string) string {
	switch layerID {
	case wf.LayerALEAuthConnectV4:
		return fmt.Sprintf("%s outbound %s (IPv4)", action, name)
	case wf.LayerALEAuthConnectV6:
		return fmt.Sprintf("%s outbound %s (IPv6)", action, name)
	case wf.LayerALEAuthRecvAcceptV4:
		return fmt.Sprintf("%s inbound %s (IPv4)", action, name)
	case wf.LayerALEAuthRecvAcceptV6:
		return fmt.Sprintf("%s inbound %s (IPv6)", action, name)
	}
	return ""
}

// permitTunInterface allows tun interface through firewall, requires luid to be set
func (f *WindowsFirewall) permitTunInterface(w weight) error {
	condition := []*wf.Match{
		{
			Field: wf.FieldIPLocalInterface,
			Op:    wf.MatchTypeEqual,
			Value: f.luid,
		},
	}
	rules, err := f.addRules("on TUN", w, condition, wf.ActionPermit, protocolAll, directionBoth)
	if err != nil {
		return err
	}
	f.tunRules = append(f.tunRules, rules...)
	return nil
}
