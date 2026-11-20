// Copyright (c) 2026 Zane Schepke / WG Tunnel
//
// Portions of this file are derived from Tailscale
// Copyright (c) Tailscale Inc & contributors
// Licensed under the BSD 3-Clause License
// See NOTICE and LICENSES/BSD-3-Clause.txt in the project root

//go:build linux

package osrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/dns"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/mark"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall"
	"github.com/wgtunnel/backend/vpn/router"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

const tag = "Router"

const (
	rulePrioBootstrap = 50
	tunnelTableID     = 52
	rulePrioMark      = 100
	rulePrioExclude   = 150
	rulePrioSuppress  = 180
	rulePrioDefault   = 200
)

type linuxRouter struct {
	iface       string
	fw          *osfirewall.LinuxFirewall
	prevConfig  *router.Config
	v4Full      bool
	v6Full      bool
	v6Available bool

	policyRules map[int][]*netlink.Rule

	ctx    context.Context
	cancel context.CancelFunc
}

// GetPhysicalInterfaceIndex stub
func (r *linuxRouter) GetPhysicalInterfaceIndex() uint32 {
	return 0
}

func New(iface string, fw firewall.Firewall, _ tun.Device) (router.Router, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &linuxRouter{
		iface:       strings.Clone(iface),
		fw:          fw.(*osfirewall.LinuxFirewall),
		v6Available: nettest.SupportsIPv6(),
		policyRules: make(map[int][]*netlink.Rule),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func (r *linuxRouter) Set(c *router.Config) error {
	newC := r.normalizeConfig(c)
	prevC := r.normalizeConfig(r.prevConfig)

	if r.isUnchanged(newC) {
		log.Debug(tag, "Config unchanged, skipping")
		return nil
	}

	link, err := netlink.LinkByName(r.iface)
	if err != nil {
		return fmt.Errorf("get link %s: %w", r.iface, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	if err := r.syncFirewallState(newC); err != nil {
		return err
	}

	r.syncDeviceParams(link, newC, prevC)

	r.cleanupPreviousState(link, newC, prevC)
	if err := r.applyNewAddresses(link, newC); err != nil {
		return err
	}

	if err := r.syncRoutingAndRules(link, newC); err != nil {
		return err
	}

	if err := r.syncDNS(newC, prevC); err != nil {
		// Protection (iface + routes + firewall) must still succeed if
		// systemd-resolved / resolv.conf apply fails.
		log.Error(tag, "sync DNS (continuing): %v", err)
	}

	r.updatePrevState(newC)
	return nil
}

func (r *linuxRouter) Close() error {
	r.cancel() // cancel any in-flight SetDNS first

	if r.prevConfig != nil {
		// short bounded context for cleanup so revert still runs after cancel
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dns.RevertDNS(ctx, r.iface); err != nil {
			log.Error(tag, "revert DNS on close: %v", err)
		}
	}

	if err := r.Set(nil); err != nil {
		log.Error(tag, "cleanup set nil: %v", err)
	}

	// Set(nil) only deletes rules this instance tracked. A previous crash or
	// "already exists, skipping" leaves orphans that survive iface delete.
	r.forceClearTunnelRouting()
	r.deletePolicyRules(netlink.FAMILY_V4)
	r.deletePolicyRules(netlink.FAMILY_V6)
	r.deleteBootstrapPolicyRules(netlink.FAMILY_V4)
	r.deleteBootstrapPolicyRules(netlink.FAMILY_V6)

	if r.fw.IsEnabled() {
		// This only releases enforcement not also required
		// by independent lockdown or another active tunnel sharing this firewall instance.
		_ = r.fw.RemoveTunnelBypasses(r.iface)
		_ = r.fw.SetTunnelRequirement(false, false)
	}
	log.Debug(tag, "Router closed")
	return nil
}

func (r *linuxRouter) forceClearTunnelRouting() {
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: tunnelTableID}, netlink.RT_FILTER_TABLE)
		if err != nil {
			log.Error(tag, "list tunnel table %d family %d: %v", tunnelTableID, fam, err)
			continue
		}
		for i := range routes {
			if err := netlink.RouteDel(&routes[i]); err != nil {
				log.Error(tag, "del leftover tunnel route %v: %v", routes[i].Dst, err)
			}
		}
	}
}

func (r *linuxRouter) cleanupPreviousState(link netlink.Link, newC, prevC *router.Config) {
	if r.prevConfig == nil {
		return
	}

	// remove old addresses
	for _, a := range prevC.TunnelAddrs {
		if !slices.Contains(newC.TunnelAddrs, a) {
			ipnet := prefixToIPNet(a)
			if err := netlink.AddrDel(link, &netlink.Addr{IPNet: ipnet}); err != nil {
				log.Error(tag, "del addr %v: %v", a, err)
			}
		}
	}

	// remove old routes
	for _, rt := range prevC.Routes {
		oldTable, oldInstalled := installedRoute(prevC, rt)
		newTable, newInstalled := installedRoute(newC, rt)
		keep := oldInstalled && newInstalled && slices.Contains(newC.Routes, rt) && oldTable == newTable
		if keep {
			continue
		}
		if !oldInstalled {
			continue
		}
		dst := prefixToIPNet(rt)
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: oldTable}
		_ = netlink.RouteDel(route)
	}

	// clean up marks
	for _, v4 := range []bool{true, false} {
		fam := netlink.FAMILY_V6
		if v4 {
			fam = netlink.FAMILY_V4
		}
		if familyPolicyRouted(prevC, v4) && !familyPolicyRouted(newC, v4) {
			r.deletePolicyRules(fam)
			r.deleteBootstrapPolicyRules(fam)
		} else if familySplit(prevC, v4) && !familySplit(newC, v4) {
			r.deleteSuppressRule(fam)
		}
		if familyIsolated(prevC, v4) && !familyIsolated(newC, v4) {
			r.deleteBlackhole(v4)
		}
	}
}

func (r *linuxRouter) normalizeConfig(c *router.Config) *router.Config {
	if c == nil {
		return &router.Config{}
	}
	return c
}

func addrExists(existing []netlink.Addr, target *net.IPNet) bool {
	for _, a := range existing {
		if a.IPNet != nil && a.IPNet.String() == target.String() {
			return true
		}
	}
	return false
}

func (r *linuxRouter) deleteExcludeRule(lr netip.Prefix) {
	fam := netlink.FAMILY_V4
	if lr.Addr().Is6() {
		fam = netlink.FAMILY_V6
	}

	dst := prefixToIPNet(lr)
	rule := netlink.NewRule()
	rule.Family = fam
	rule.Priority = rulePrioExclude
	rule.Dst = dst
	rule.Table = unix.RT_TABLE_MAIN

	// ignore the error if rule is already gone
	if err := netlink.RuleDel(rule); err != nil {
		log.Debug(tag, "del exclude rule %v: %v (ignored)", lr, err)
	}
}

func (r *linuxRouter) isUnchanged(newC *router.Config) bool {
	if r.prevConfig == nil {
		return false
	}
	return newC.Equal(r.prevConfig)
}

func (r *linuxRouter) updatePrevState(newC *router.Config) {
	r.v4Full = familyUsable(newC, true)
	r.v6Full = familyUsable(newC, false)
	r.prevConfig = newC.Clone()
	log.Debug(tag, "Router state updated: full v4=%v v6=%v", r.v4Full, r.v6Full)
}

func (r *linuxRouter) syncFirewallState(newC *router.Config) error {
	// A full tunnel blocks a family the tun cannot carry
	requiresKSv4 := familyIsolated(newC, true)
	requiresKSv6 := familyIsolated(newC, false)
	requiresKS := requiresKSv4 || requiresKSv6

	if !requiresKS && !r.fw.IsEnabled() {
		// not full tun and independent ks is not enabled, do nothing
		return nil
		// handle cleanup
	} else if newC.Equal(&router.Config{}) && r.fw.IsEnabled() {
		if err := r.fw.RemoveTunnelBypasses(r.iface); err != nil {
			return fmt.Errorf("remove tunnel bypasses: %w", err)
		}
		if err := r.fw.SetTunnelRequirement(false, false); err != nil {
			return fmt.Errorf("release tunnel kill-switch requirement: %w", err)
		}
		return nil
	}

	if requiresKS && !r.fw.IsEnabled() {
		// set persist to false as this kill switch is only required for this tun
		r.fw.SetPersist(false)
	}
	if err := r.fw.SetTunnelRequirement(requiresKSv4, requiresKSv6); err != nil {
		return fmt.Errorf("sync firewall tunnel requirement: %w", err)
	}

	// kill switch is active, set our bypass rules for tun
	if r.fw.IsEnabled() {
		if err := r.fw.AddTunnelBypasses(r.iface); err != nil {
			return fmt.Errorf("add firewall bypasses: %w", err)
		}
	}

	return nil
}

func (r *linuxRouter) syncDeviceParams(link netlink.Link, newC, prevC *router.Config) {
	// sync mtu
	if newC.MTU > 0 && newC.MTU != prevC.MTU {
		_ = netlink.LinkSetMTU(link, newC.MTU)
	}

	// sync ListenPort for fw
	if newC.ListenPort != 0 && newC.ListenPort != prevC.ListenPort {
		_ = r.fw.SetTunnelPort(newC.ListenPort)
	}
}

func (r *linuxRouter) syncDNS(newC, prevC *router.Config) error {
	v4Full := familyUsable(newC, true)
	v6Full := familyUsable(newC, false)
	prevV4Full := familyUsable(prevC, true)
	prevV6Full := familyUsable(prevC, false)

	dnsChanged := !slices.Equal(newC.DNS, prevC.DNS) ||
		!slices.Equal(newC.SearchDomains, prevC.SearchDomains)
	stateChanged := (v4Full != prevV4Full) || (v6Full != prevV6Full)

	if !dnsChanged && !stateChanged {
		return nil
	}

	return dns.SetDNS(
		r.ctx,
		r.iface,
		newC.DNS,
		newC.SearchDomains,
	)
}

func (r *linuxRouter) applyNewAddresses(link netlink.Link, newC *router.Config) error {
	existingAddrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)

	for _, a := range newC.TunnelAddrs {
		if a.Addr().Is6() && !r.v6Available {
			continue
		}

		ipNet := prefixToIPNet(a)

		if !addrExists(existingAddrs, ipNet) {
			if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: ipNet}); err != nil {
				return fmt.Errorf("failed to add addr %v: %w", a, err)
			}
		}
	}
	return nil
}

func (r *linuxRouter) syncRoutingAndRules(link netlink.Link, newC *router.Config) error {
	families := []int{netlink.FAMILY_V4}
	if r.v6Available {
		families = append(families, netlink.FAMILY_V6)
	}

	for _, fam := range families {
		v4 := fam == netlink.FAMILY_V4
		isolated := familyIsolated(newC, v4)
		usable := familyUsable(newC, v4)

		if familyPolicyRouted(newC, v4) {
			if err := r.addPolicyRules(fam); err != nil {
				return err
			}
			// add bootstrap mark rule for DNS bootstrap
			if err := r.addBootstrapPolicyRules(fam); err != nil {
				return err
			}
		}
		if familySplit(newC, v4) {
			if err := r.addSuppressRule(fam); err != nil {
				return err
			}
		}

		if isolated && !usable {
			// AllowedIPs asked to capture this family, or the other family is a
			// full tunnel, but the tun has no address here so we blackhole it.
			if err := r.replaceBlackhole(v4); err != nil {
				return err
			}
			continue
		}
		r.deleteBlackhole(v4)

		routes := filterRoutes(newC.Routes, v4)
		for _, rt := range routes {
			table, install := installedRoute(newC, rt)
			if !install {
				continue
			}
			if err := r.replaceRouteIdempotent(link, rt, table); err != nil {
				return err
			}
		}
	}
	return nil
}

// installedRoute is where a prefix is programmed. The second result is false
// when the family is blackholed and the prefix must not be pointed at the tun.
func installedRoute(c *router.Config, rt netip.Prefix) (table int, ok bool) {
	v4 := rt.Addr().Is4()
	if familyUsable(c, v4) || familySplit(c, v4) {
		return tunnelTableID, true
	}
	if familyIsolated(c, v4) {
		return 0, false
	}
	return unix.RT_TABLE_MAIN, true
}

// familySplit reports a family the tunnel routes only part of ()routes but no
// default route). Those routes go in the tunnel table behind the fwmark rule like
// a full tunnel's.
func familySplit(c *router.Config, v4 bool) bool {
	if c == nil || familyIsolated(c, v4) {
		return false
	}
	return len(filterRoutes(c.Routes, v4)) > 0
}

// familyPolicyRouted reports a family whose routes live in the tunnel table and
// need the fwmark and tunnel table rules.
func familyPolicyRouted(c *router.Config, v4 bool) bool {
	return familyIsolated(c, v4) || familySplit(c, v4)
}

func defaultPrefix(v4 bool) netip.Prefix {
	if v4 {
		return netip.MustParsePrefix("0.0.0.0/0")
	}
	return netip.MustParsePrefix("::/0")
}

func (r *linuxRouter) replaceBlackhole(v4 bool) error {
	route := &netlink.Route{
		Dst:   prefixToIPNet(defaultPrefix(v4)),
		Table: tunnelTableID,
		Type:  unix.RTN_BLACKHOLE,
	}
	if err := netlink.RouteReplace(route); err != nil {
		fam := "ipv6"
		if v4 {
			fam = "ipv4"
		}
		return fmt.Errorf("blackhole %s: %w", fam, err)
	}
	return nil
}

func (r *linuxRouter) deleteBlackhole(v4 bool) {
	route := &netlink.Route{
		Dst:   prefixToIPNet(defaultPrefix(v4)),
		Table: tunnelTableID,
		Type:  unix.RTN_BLACKHOLE,
	}
	_ = netlink.RouteDel(route)
}

func (r *linuxRouter) addBootstrapPolicyRules(family int) error {
	mask := uint32(mark.LinuxFwmarkMaskNum)
	rule := netlink.NewRule()
	rule.Family = family
	rule.Mark = mark.LinuxBootstrapMarkNum
	rule.Mask = &mask
	rule.Priority = 50              // set as high priority, above main tunnel rules
	rule.Table = unix.RT_TABLE_MAIN // force bypass to ISP table

	return r.addRuleIdempotent(rule)
}

func (r *linuxRouter) deleteBootstrapPolicyRules(family int) error {
	r.sweepPolicyRules(family, func(rule netlink.Rule) bool {
		return rule.Priority == rulePrioBootstrap && rule.Mark == mark.LinuxBootstrapMarkNum
	})
	return nil
}

func isFileExists(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrExist) || errors.Is(err, unix.EEXIST) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") || strings.Contains(msg, "exists")
}

func (r *linuxRouter) addRuleIdempotent(rule *netlink.Rule) error {
	rules, err := netlink.RuleList(rule.Family)
	if err != nil {
		return err
	}

	for _, existing := range rules {
		if existing.Mark == rule.Mark && existing.Priority == rule.Priority && existing.Table == rule.Table {
			return nil // Already exists
		}
	}
	if err := netlink.RuleAdd(rule); err != nil && !isFileExists(err) {
		return err
	}
	return nil
}

func (r *linuxRouter) replaceRouteIdempotent(link netlink.Link, rt netip.Prefix, table int) error {
	dst := prefixToIPNet(rt)
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Table:     table,
		Type:      unix.RTN_UNICAST,
	}
	return netlink.RouteReplace(route)
}

// filterRoutes returns routes for v4 (true) or v6 (false).
func filterRoutes(routes []netip.Prefix, v4 bool) []netip.Prefix {
	var filtered []netip.Prefix
	for _, rt := range routes {
		if (v4 && rt.Addr().Is4()) || (!v4 && rt.Addr().Is6()) {
			filtered = append(filtered, rt)
		}
	}
	return filtered
}

// prefixToIPNet converts netip.Prefix to *net.IPNet.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	if !p.IsValid() {
		return nil
	}
	bits := p.Bits()
	addr := p.Addr()
	ip := net.IP(addr.AsSlice())
	mask := net.CIDRMask(bits, addr.BitLen())
	return &net.IPNet{IP: ip, Mask: mask}
}

// addPolicyRules adds mark-based and default tunnel table rules for the family.
func (r *linuxRouter) addPolicyRules(fam int) error {
	rules, err := netlink.RuleList(fam)
	if err != nil {
		return fmt.Errorf("list rules fam %d: %w", fam, err)
	}

	// Mark rule: fwmark bypass -> main
	markRule := netlink.NewRule()
	markRule.Family = fam
	markRule.Priority = rulePrioMark
	markRule.Mark = mark.LinuxBypassMarkNum
	markRule.Table = unix.RT_TABLE_MAIN

	markExists := false
	for _, existing := range rules {
		if existing.Priority == markRule.Priority && existing.Mark == markRule.Mark && existing.Table == markRule.Table {
			markExists = true
			break
		}
	}
	if !markExists {
		if err := netlink.RuleAdd(markRule); err != nil && !errors.Is(err, os.ErrExist) && !isFileExists(err) {
			return fmt.Errorf("add mark rule fam %d: %w", fam, err)
		}
	} else {
		log.Debug(tag, "Mark rule fam %d already exists, adopting", fam)
	}
	r.policyRules[fam] = append(r.policyRules[fam], markRule)

	defaultRule := netlink.NewRule()
	defaultRule.Family = fam
	defaultRule.Priority = rulePrioDefault
	defaultRule.Table = tunnelTableID

	defaultExists := false
	for _, existing := range rules {
		if existing.Priority == defaultRule.Priority && existing.Table == defaultRule.Table && existing.Dst == nil {
			defaultExists = true
			break
		}
	}
	if !defaultExists {
		if err := netlink.RuleAdd(defaultRule); err != nil && !errors.Is(err, os.ErrExist) && !isFileExists(err) {
			return fmt.Errorf("add default tunnel rule fam %d: %w", fam, err)
		}
	} else {
		log.Debug(tag, "Default tunnel rule fam %d already exists, adopting", fam)
	}
	r.policyRules[fam] = append(r.policyRules[fam], defaultRule)
	return nil
}

// addSuppressRule makes the main table win over the tunnel table for anything
// it routes more specifically than its default route, the LAN and other local
// networks included.
func (r *linuxRouter) addSuppressRule(fam int) error {
	rule := netlink.NewRule()
	rule.Family = fam
	rule.Priority = rulePrioSuppress
	rule.Table = unix.RT_TABLE_MAIN
	rule.SuppressPrefixlen = 0
	if err := r.addRuleIdempotent(rule); err != nil {
		return err
	}
	r.policyRules[fam] = append(r.policyRules[fam], rule)
	return nil
}

func (r *linuxRouter) deleteSuppressRule(fam int) {
	kept := r.policyRules[fam][:0]
	for _, rule := range r.policyRules[fam] {
		if rule.Priority != rulePrioSuppress {
			kept = append(kept, rule)
		}
	}
	r.policyRules[fam] = kept
	r.sweepPolicyRules(fam, isSuppressRule)
}

func isSuppressRule(rule netlink.Rule) bool {
	return rule.Priority == rulePrioSuppress && rule.Table == unix.RT_TABLE_MAIN && rule.SuppressPrefixlen == 0
}

// deletePolicyRules deletes the policy rules for the family.
func (r *linuxRouter) deletePolicyRules(fam int) {
	for _, rule := range r.policyRules[fam] {
		if err := netlink.RuleDel(rule); err != nil {
			log.Debug(tag, "del policy rule fam %d (prio %d): %v (ignored)", fam, rule.Priority, err)
		}
	}
	r.policyRules[fam] = nil
	r.sweepPolicyRules(fam, isTrackedTunnelPolicyRule)
}

func isTrackedTunnelPolicyRule(rule netlink.Rule) bool {
	switch rule.Priority {
	case rulePrioMark:
		return rule.Mark == mark.LinuxBypassMarkNum && rule.Table == unix.RT_TABLE_MAIN
	case rulePrioSuppress:
		return isSuppressRule(rule)
	case rulePrioDefault:
		return rule.Table == tunnelTableID
	default:
		return false
	}
}

func (r *linuxRouter) sweepPolicyRules(fam int, match func(netlink.Rule) bool) {
	rules, err := netlink.RuleList(fam)
	if err != nil {
		log.Debug(tag, "list policy rules fam %d: %v (ignored)", fam, err)
		return
	}
	for i := range rules {
		rule := rules[i]
		if !match(rule) {
			continue
		}
		if err := netlink.RuleDel(&rule); err != nil {
			log.Debug(tag, "del leftover policy rule fam %d (prio %d): %v (ignored)", fam, rule.Priority, err)
			continue
		}
		log.Debug(tag, "Deleted leftover policy rule fam %d prio %d table %d", fam, rule.Priority, rule.Table)
	}
}
