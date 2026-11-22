// Copyright (c) 2026 Zane Schepke / WG Tunnel
//
// Portions of this file are derived from Tailscale
// Copyright (c) Tailscale Inc & contributors
// Licensed under the BSD 3-Clause License
// See NOTICE and LICENSES/BSD-3-Clause.txt in the project root

//go:build darwin

package osrouter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/network"
	"github.com/wgtunnel/backend/vpn/dns"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall"
	"github.com/wgtunnel/backend/vpn/router"
	"golang.org/x/net/nettest"
)

const tag = "Router"

var errRouteExists = errors.New("route exists")

type darwinRouter struct {
	iface       string
	fw          *osfirewall.DarwinFirewall
	prevConfig  *router.Config
	v6Available bool

	physicalName    string
	physicalIfIndex uint32
	savedGateway4   string
	savedGateway6   string

	// installed is prefixes we actually added on the tun. Darwin `route delete`
	// keys on dest/netmask, so deleting a prefix we failed to add (File exists)
	// removes the physical connected route instead.
	installed map[netip.Prefix]struct{}
	// displaced is the physical route that was present before a successful add
	// of the same dest/netmask, restored when that tun route is removed.
	displaced map[netip.Prefix]darwinNetRoute

	// blackhole4/6 are the /1 blackhole routes for a family the tun cannot carry.
	blackhole4 bool
	blackhole6 bool

	ctx    context.Context
	cancel context.CancelFunc
}

func (r *darwinRouter) GetPhysicalInterfaceIndex() uint32 {
	return r.physicalIfIndex
}

func New(iface string, fw firewall.Firewall, tunnel tun.Device) (router.Router, error) {
	name := iface
	if tunnel != nil {
		if n, err := tunnel.Name(); err == nil && n != "" {
			name = n
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &darwinRouter{
		iface:       name,
		fw:          fw.(*osfirewall.DarwinFirewall),
		v6Available: nettest.SupportsIPv6(),
		installed:   make(map[netip.Prefix]struct{}),
		displaced:   make(map[netip.Prefix]darwinNetRoute),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func (r *darwinRouter) Set(c *router.Config) error {
	newC := c
	if newC == nil {
		newC = &router.Config{}
	}
	prevC := r.prevConfig
	if prevC == nil {
		prevC = &router.Config{}
	}
	if newC.Equal(prevC) {
		log.Debug(tag, "Config unchanged, skipping")
		return nil
	}

	if err := r.ifconfig(r.iface, "up"); err != nil {
		return fmt.Errorf("ifconfig up: %w", err)
	}

	if err := r.syncFirewallState(newC); err != nil {
		return err
	}

	if newC.MTU > 0 && newC.MTU != prevC.MTU {
		_ = r.ifconfig(r.iface, "mtu", fmt.Sprintf("%d", newC.MTU))
	}
	if newC.ListenPort != 0 && newC.ListenPort != prevC.ListenPort {
		_ = r.fw.SetTunnelPort(newC.ListenPort)
	}

	if r.prevConfig == nil {
		r.capturePhysicalDefaults()
	}

	r.cleanupPreviousState(newC, prevC)
	if err := r.applyAddresses(newC); err != nil {
		return err
	}
	// Drop blackholes before tun /1s are added, or route add hits "file exists"
	// and leaves the blackhole in place.
	if err := r.deleteUnwantedBlackholes(newC); err != nil {
		return err
	}
	if err := r.applyRoutes(newC, prevC); err != nil {
		return err
	}
	if err := r.installBlackholes(newC); err != nil {
		return err
	}
	if err := r.protectPeerEndpoints(newC); err != nil {
		log.Error(tag, "peer endpoint routes: %v", err)
	}
	_ = r.fw.UpdatePermittedRoutes(newC.PeerEndpoints)

	if err := r.syncDNS(newC, prevC); err != nil {
		log.Error(tag, "sync DNS (continuing): %v", err)
	}

	r.prevConfig = newC.Clone()
	return nil
}

func (r *darwinRouter) Close() error {
	r.cancel()
	if r.prevConfig != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dns.RevertDNS(ctx, r.iface); err != nil {
			log.Error(tag, "revert DNS on close: %v", err)
		}
	}
	if err := r.Set(nil); err != nil {
		log.Error(tag, "cleanup set nil: %v", err)
	}
	if r.fw.IsEnabled() {
		_ = r.fw.RemoveTunnelBypasses(r.iface)
		_ = r.fw.SetTunnelRequirement(false, false)
	}
	log.Debug(tag, "Router closed")
	return nil
}

func (r *darwinRouter) syncFirewallState(newC *router.Config) error {
	requiresKSv4 := familyIsolated(newC, true)
	requiresKSv6 := familyIsolated(newC, false)
	requiresKS := requiresKSv4 || requiresKSv6

	if !requiresKS && !r.fw.IsEnabled() {
		return nil
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
		r.fw.SetPersist(false)
	}
	if err := r.fw.SetTunnelRequirement(requiresKSv4, requiresKSv6); err != nil {
		return fmt.Errorf("sync firewall tunnel requirement: %w", err)
	}
	if r.fw.IsEnabled() {
		if err := r.fw.AddTunnelBypasses(r.iface); err != nil {
			return fmt.Errorf("add firewall bypasses: %w", err)
		}
	}
	return nil
}

func (r *darwinRouter) applyAddresses(newC *router.Config) error {
	for _, a := range newC.TunnelAddrs {
		if a.Addr().Is6() && !r.v6Available {
			continue
		}
		inet := "inet"
		if a.Addr().Is6() {
			inet = "inet6"
		}
		// Tailscale userspace BSD: ifconfig utun inet addr addr
		if err := r.ifconfig(r.iface, inet, a.String(), a.Addr().String()); err != nil {
			return fmt.Errorf("ifconfig addr %v: %w", a, err)
		}
	}
	return nil
}

func (r *darwinRouter) cleanupPreviousState(newC, prevC *router.Config) {
	if r.prevConfig == nil {
		return
	}
	for _, a := range prevC.TunnelAddrs {
		if slices.Contains(newC.TunnelAddrs, a) {
			continue
		}
		inet := "inet"
		if a.Addr().Is6() {
			inet = "inet6"
		}
		_ = r.ifconfig(r.iface, inet, a.String(), "-alias")
	}
	for _, rt := range prevC.Routes {
		if slices.Contains(newC.Routes, rt) {
			continue
		}
		if _, ok := r.installed[rt]; ok {
			_ = r.route("delete", rt, r.iface, false)
			delete(r.installed, rt)
		}
		r.restoreDisplaced(rt)
		if rt.Bits() == 0 {
			r.restoreDefault(rt.Addr().Is4())
		}
	}
	for _, p := range prevC.PeerEndpoints {
		if slices.Contains(newC.PeerEndpoints, p) {
			continue
		}
		_ = r.deleteHostRoute(p.Addr())
	}
}

// deleteUnwantedBlackholes removes /1 blackholes before tun routes are added.
func (r *darwinRouter) deleteUnwantedBlackholes(newC *router.Config) error {
	if !familyUnsupported(newC, true) {
		if err := r.setBlackhole(true, false); err != nil {
			return err
		}
	}
	if !familyUnsupported(newC, false) {
		if err := r.setBlackhole(false, false); err != nil {
			return err
		}
	}
	return nil
}

func (r *darwinRouter) installBlackholes(newC *router.Config) error {
	if err := r.setBlackhole(true, familyUnsupported(newC, true)); err != nil {
		return err
	}
	want6 := familyUnsupported(newC, false) && r.v6Available
	return r.setBlackhole(false, want6)
}

func (r *darwinRouter) setBlackhole(v4 bool, want bool) error {
	have := r.blackhole4
	if !v4 {
		have = r.blackhole6
	}
	if want == have {
		return nil
	}
	op := "add"
	if !want {
		op = "delete"
	}
	for _, p := range splitDefaultRoute(!v4) {
		if err := r.routeBlackhole(op, p); err != nil {
			return err
		}
	}
	if v4 {
		r.blackhole4 = want
	} else {
		r.blackhole6 = want
	}
	return nil
}

func (r *darwinRouter) routeBlackhole(op string, p netip.Prefix) error {
	inet := "inet"
	if p.Addr().Is6() {
		inet = "inet6"
	}
	args := []string{"-q", "-n", op, "-" + inet, p.Masked().String(), "-blackhole"}
	cmd := exec.Command("route", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.ToLower(string(out))
		if op == "delete" && (strings.Contains(msg, "not in table") || strings.Contains(msg, "not exist")) {
			return nil
		}
		if op == "add" && strings.Contains(msg, "file exists") {
			return nil
		}
		return fmt.Errorf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *darwinRouter) applyRoutes(newC, prevC *router.Config) error {
	for _, rt := range newC.Routes {
		if familyUnsupported(newC, rt.Addr().Is4()) {
			// Still in the config, so cleanup will not remove a tun route
			// installed while this family was usable.
			if _, ok := r.installed[rt]; ok {
				_ = r.route("delete", rt, r.iface, false)
				delete(r.installed, rt)
				r.restoreDisplaced(rt)
			}
			continue
		}
		// Present last time only means it is already on the tun when that sync
		// was allowed to install it.
		if slices.Contains(prevC.Routes, rt) && !familyUnsupported(prevC, rt.Addr().Is4()) {
			continue
		}
		if rt.Addr().Is6() && !r.v6Available {
			continue
		}
		existing, exact := r.lookupExactRoute(rt)
		if exact && existing.iface == r.iface {
			r.installed[rt] = struct{}{}
			continue
		}
		if exact && rt.Bits() != 0 && existing.iface != "" && existing.iface != r.iface {
			r.displaced[rt] = existing
		}
		err := r.route("add", rt, r.iface, false)
		if errors.Is(err, errRouteExists) {
			delete(r.displaced, rt)
			log.Debug(tag, "skip tun route %v: already exists on %s", rt, existing.iface)
			continue
		}
		if err != nil {
			delete(r.displaced, rt)
			return fmt.Errorf("route add %v: %w", rt, err)
		}
		r.installed[rt] = struct{}{}
	}
	return nil
}

func (r *darwinRouter) lookupExactRoute(p netip.Prefix) (darwinNetRoute, bool) {
	args := []string{"-n", "get"}
	if p.Addr().Is6() {
		args = append(args, "-inet6")
	}
	args = append(args, p.Masked().Addr().String())
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return darwinNetRoute{}, false
	}
	rt, ok := parseDarwinRouteGet(string(out), p.Addr().Is6())
	if !ok || rt.dst != p.Masked() {
		return darwinNetRoute{}, false
	}
	return rt, true
}

func (r *darwinRouter) restoreDisplaced(p netip.Prefix) {
	saved, ok := r.displaced[p]
	if !ok {
		return
	}
	delete(r.displaced, p)
	if saved.iface == "" || saved.iface == r.iface {
		return
	}
	inet := "inet"
	if p.Addr().Is6() {
		inet = "inet6"
	}
	nstr := p.Masked().String()
	var args []string
	if saved.viaGateway() {
		args = []string{"-q", "-n", "add", "-" + inet, nstr, saved.gateway}
	} else {
		args = []string{"-q", "-n", "add", "-" + inet, nstr, "-iface", saved.iface}
	}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "exists") {
		log.Error(tag, "restore %v via %s: %v (%s)", p, saved.iface, err, strings.TrimSpace(string(out)))
		return
	}
	log.Debug(tag, "restored %v on %s", p, saved.iface)
}

func (r *darwinRouter) protectPeerEndpoints(newC *router.Config) error {
	if r.physicalName == "" {
		r.capturePhysicalDefaults()
	}
	for _, p := range newC.PeerEndpoints {
		if !p.IsValid() || p.Addr().IsPrivate() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		gw := r.savedGateway4
		if p.Addr().Is6() {
			gw = r.savedGateway6
		}
		if gw != "" {
			if err := r.addHostRoute(p.Addr(), gw); err != nil {
				log.Debug(tag, "protect peer %v via %s: %v", p.Addr(), gw, err)
			}
			continue
		}
		if r.physicalName != "" {
			if err := r.route("add", p, r.physicalName, true); err != nil {
				log.Debug(tag, "protect peer %v ifscope %s: %v", p, r.physicalName, err)
			}
		}
	}
	return nil
}

func (r *darwinRouter) capturePhysicalDefaults() {
	d4 := network.LookupPhysicalDefault4()
	if d4.IfName != "" {
		r.physicalName = d4.IfName
		r.physicalIfIndex = d4.IfIndex
		r.savedGateway4 = d4.Gateway
		log.Debug(tag, "physical default v4 gw=%s if=%s", d4.Gateway, d4.IfName)
	}
	d6 := network.LookupPhysicalDefault6()
	if d6.IfName != "" {
		if r.physicalName == "" {
			r.physicalName = d6.IfName
			r.physicalIfIndex = d6.IfIndex
		}
		r.savedGateway6 = d6.Gateway
		log.Debug(tag, "physical default v6 gw=%s if=%s", d6.Gateway, d6.IfName)
	}
}

func (r *darwinRouter) restoreDefault(v4 bool) {
	gw := r.savedGateway4
	inet := "inet"
	if !v4 {
		gw = r.savedGateway6
		inet = "inet6"
	}
	if gw == "" {
		return
	}
	args := []string{"-q", "-n", "add", "-" + inet, "default", gw}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "exists") {
		log.Error(tag, "restore default %s via %s: %v (%s)", inet, gw, err, strings.TrimSpace(string(out)))
		return
	}
	log.Debug(tag, "restored default %s via %s", inet, gw)
}

func (r *darwinRouter) deleteHostRoute(addr netip.Addr) error {
	inet := "inet"
	if addr.Is6() {
		inet = "inet6"
	}
	args := []string{"-q", "-n", "delete", "-" + inet, "-host", addr.String()}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		msg := strings.ToLower(string(out))
		if strings.Contains(msg, "not in table") || strings.Contains(msg, "not exist") {
			return nil
		}
		return fmt.Errorf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *darwinRouter) addHostRoute(addr netip.Addr, gw string) error {
	inet := "inet"
	if addr.Is6() {
		inet = "inet6"
	}
	args := []string{"-q", "-n", "add", "-" + inet, "-host", addr.String(), gw}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "exists") {
		return fmt.Errorf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *darwinRouter) syncDNS(newC, prevC *router.Config) error {
	if slices.Equal(newC.DNS, prevC.DNS) && slices.Equal(newC.SearchDomains, prevC.SearchDomains) {
		return nil
	}
	return dns.SetDNS(r.ctx, r.iface, newC.DNS, newC.SearchDomains)
}

func (r *darwinRouter) ifconfig(args ...string) error {
	cmd := exec.Command("ifconfig", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// BSD/macOS allows only one default-route entry per address family in the
// main table. Splitting into two complementary /1 routes avoids this issue
// since both are specific than any /0 and win via longest-prefix-match without
// touching the existing default, the same technique used for Windows
func (r *darwinRouter) route(op string, p netip.Prefix, iface string, ifscope bool) error {
	if p.Bits() == 0 {
		added := false
		for _, half := range splitDefaultRoute(p.Addr().Is6()) {
			err := r.routeSingle(op, half, iface, ifscope)
			if err == nil {
				added = true
				continue
			}
			if errors.Is(err, errRouteExists) {
				continue
			}
			return err
		}
		if op == "add" && !added {
			return errRouteExists
		}
		return nil
	}
	return r.routeSingle(op, p, iface, ifscope)
}

func splitDefaultRoute(isV6 bool) []netip.Prefix {
	if isV6 {
		return []netip.Prefix{
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
}

func (r *darwinRouter) routeSingle(op string, p netip.Prefix, iface string, ifscope bool) error {
	inet := "inet"
	if p.Addr().Is6() {
		inet = "inet6"
	}
	nstr := p.Masked().String()
	args := []string{"-q", "-n", op, "-" + inet, nstr}
	if ifscope {
		args = append(args, "-ifscope", iface)
	} else {
		args = append(args, "-iface", iface)
	}
	cmd := exec.Command("route", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.ToLower(string(out))
		if op == "delete" && (strings.Contains(msg, "not in table") || strings.Contains(msg, "not exist")) {
			return nil
		}
		if op == "add" && strings.Contains(msg, "file exists") {
			return errRouteExists
		}
		return fmt.Errorf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
