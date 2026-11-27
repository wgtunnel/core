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
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/network"
	"github.com/wgtunnel/backend/util"
	"github.com/wgtunnel/backend/vpn/dns"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall"
	"github.com/wgtunnel/backend/vpn/router"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

const tag = "Router"

var errRouteExists = errors.New("route exists")

type darwinRouter struct {
	// mu serializes Set with the route watcher.
	mu sync.Mutex

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
	// skipped is prefixes left off the tun because another interface already holds
	// the same dest/netmask, usually a LAN on the same subnet. The route watcher
	// retries them, so the tunnel takes them once that network is gone.
	skipped map[netip.Prefix]struct{}
	// scoped4/6 are the physical defaults scoped to their interface that this router
	// added, see syncScopedDefaults.
	scoped4, scoped6 scopedDefault

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
	r := &darwinRouter{
		iface:       name,
		fw:          fw.(*osfirewall.DarwinFirewall),
		v6Available: nettest.SupportsIPv6(),
		installed:   make(map[netip.Prefix]struct{}),
		displaced:   make(map[netip.Prefix]darwinNetRoute),
		skipped:     make(map[netip.Prefix]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
	go r.watchRoutes()
	return r, nil
}

func (r *darwinRouter) Set(c *router.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
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
		if !newC.Equal(&router.Config{}) {
			return fmt.Errorf("ifconfig up: %w", err)
		}
		// A start that fails after the device closed the tun lands here. The service, DNS,
		// forwarding and scoped default it published outlive the tun and must still go.
		log.Debug(tag, "teardown without %s: %v", r.iface, err)
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

	// Drop the service before routes go, so configd restores the physical default
	// itself. Also clears keys a crashed run left behind.
	svc4, svc6 := r.tunnelServiceAddrs(newC)
	if !svc4.IsValid() && !svc6.IsValid() {
		if err := dns.RemoveTunnelService(); err != nil {
			log.Error(tag, "remove tunnel service: %v", err)
		}
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
	r.syncForwarding(newC)
	if err := r.protectPeerEndpoints(newC); err != nil {
		log.Error(tag, "peer endpoint routes: %v", err)
	}
	r.syncScopedDefaults(newC)
	_ = r.fw.UpdatePermittedRoutes(newC.PeerEndpoints)

	if err := r.syncDNS(newC, prevC); err != nil {
		log.Error(tag, "sync DNS (continuing): %v", err)
	}
	if svc4.IsValid() || svc6.IsValid() {
		if err := dns.SetTunnelService(r.iface, svc4, svc6); err != nil {
			log.Error(tag, "publish tunnel service (continuing): %v", err)
		}
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
		r.removeTunRoute(rt)
		delete(r.skipped, rt)
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
				r.removeTunRoute(rt)
				r.restoreDisplaced(rt)
			}
			delete(r.skipped, rt)
			continue
		}
		// Present last time only means it is already on the tun when that sync
		// was allowed to install it.
		if _, skipped := r.skipped[rt]; !skipped &&
			slices.Contains(prevC.Routes, rt) && !familyUnsupported(prevC, rt.Addr().Is4()) {
			continue
		}
		if rt.Addr().Is6() && !r.v6Available {
			continue
		}
		if err := r.installRoute(rt); err != nil {
			return err
		}
	}
	return nil
}

func (r *darwinRouter) installRoute(rt netip.Prefix) error {
	if rt.Bits() != 0 {
		if owners, cloned, err := routeOwners(); err == nil {
			tun, other := r.heldBy(owners, rt)
			if tun {
				r.installed[rt] = struct{}{}
				delete(r.skipped, rt)
				return nil
			}
			if other {
				r.skip(rt)
				return nil
			}
			// A cached host entry is not a route to give back later. Taking it for one
			// turned an ARP or path cache into a static route on disconnect, which then
			// kept the next tunnel's route (the FakeDNS /32 on a split tunnel) off it.
			if cloned[rt.Masked()] {
				_ = r.deleteHostRoute(rt.Addr())
			}
			return r.addTunRoute(rt)
		}
	}
	existing, exact := r.lookupExactRoute(rt)
	if exact && existing.iface == r.iface {
		r.installed[rt] = struct{}{}
		delete(r.skipped, rt)
		return nil
	}
	if exact && rt.Bits() != 0 && existing.iface != "" && existing.iface != r.iface {
		r.displaced[rt] = existing
	}
	return r.addTunRoute(rt)
}

func (r *darwinRouter) addTunRoute(rt netip.Prefix) error {
	err := r.route("add", rt, r.iface, false)
	if errors.Is(err, errRouteExists) {
		delete(r.displaced, rt)
		if rt.Bits() == 0 {
			// Another VPN holds the /1 halves. There is no local network to wait out.
			log.Error(tag, "%v: another interface already holds the default route halves", rt)
			return nil
		}
		r.skip(rt)
		return nil
	}
	if err != nil {
		delete(r.displaced, rt)
		return fmt.Errorf("route add %v: %w", rt, err)
	}
	if _, was := r.skipped[rt]; was {
		log.Debug(tag, "%v now on the tunnel", rt)
		delete(r.skipped, rt)
	}
	r.installed[rt] = struct{}{}
	return nil
}

// skip leaves rt off the tun while a local network on the same subnet routes it.
func (r *darwinRouter) skip(rt netip.Prefix) {
	if _, seen := r.skipped[rt]; !seen {
		log.Error(tag, "%v stays off the tunnel: a local network on the same subnet already routes it", rt)
	}
	delete(r.installed, rt)
	r.skipped[rt] = struct{}{}
}

// removeTunRoute deletes rt only while the tun still holds it. route delete matches on
// dest/netmask alone, so a prefix macOS has since handed back to a LAN would lose that
// LAN's connected route instead.
func (r *darwinRouter) removeTunRoute(rt netip.Prefix) {
	if _, ok := r.installed[rt]; !ok {
		return
	}
	delete(r.installed, rt)
	if rt.Bits() != 0 {
		owners, _, err := routeOwners()
		if err != nil {
			return
		}
		if tun, _ := r.heldBy(owners, rt); !tun {
			return
		}
	}
	_ = r.route("delete", rt, r.iface, false)
}

func (r *darwinRouter) heldBy(owners map[netip.Prefix][]int, rt netip.Prefix) (tun, other bool) {
	idx := -1
	if ifi, err := net.InterfaceByName(r.iface); err == nil {
		idx = ifi.Index
	}
	for _, o := range owners[rt.Masked()] {
		if o == idx {
			tun = true
		} else {
			other = true
		}
	}
	return tun, other
}

// reconcileRoutes follows the OS. A network that comes up on the subnet of a tun
// prefix takes it back (macOS replaces our route with its connected one), and a
// skipped prefix goes on the tun once its network is gone.
func (r *darwinRouter) reconcileRoutes() {
	owners, _, err := routeOwners()
	if err != nil {
		log.Debug(tag, "route table: %v", err)
		return
	}
	for rt := range r.installed {
		if rt.Bits() == 0 {
			continue
		}
		tun, other := r.heldBy(owners, rt)
		switch {
		case tun:
		case other:
			r.skip(rt)
		default:
			delete(r.installed, rt)
			if err := r.installRoute(rt); err != nil {
				log.Error(tag, "reinstall %v: %v", rt, err)
			}
		}
	}
	for rt := range r.skipped {
		if _, other := r.heldBy(owners, rt); other {
			continue
		}
		if err := r.installRoute(rt); err != nil {
			log.Error(tag, "retry %v: %v", rt, err)
		}
	}
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
		if !endpointNeedsProtection(p, newC.TunnelAddrs) {
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

// watchRoutes keeps the peer endpoint routes in place while the router lives. macOS
// deletes them when an interface's address is reapplied (DHCP renew, a service
// toggle, a network switch), which sends the tunnel's own traffic into the tunnel.
// Like Mullvad, any routing table change re-checks them against the current physical
// default.
func (r *darwinRouter) watchRoutes() {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Error(tag, "route watch socket: %v", err)
		return
	}
	// A receive timeout lets the reader notice Close without the fd being closed under
	// a blocked read, where the number could be reused by another open.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	events := make(chan struct{}, 1)
	go func() {
		defer unix.Close(fd)
		buf := make([]byte, 2048)
		for r.ctx.Err() == nil {
			n, err := unix.Read(fd, buf)
			switch {
			case err == unix.EAGAIN || err == unix.EINTR:
				continue
			case err == nil && !network.IsRouteChange(buf[:n]):
				continue
			case err != nil && err != unix.ENOBUFS:
				log.Error(tag, "route watch read: %v", err)
				return
			}
			select {
			case events <- struct{}{}:
			default:
			}
		}
	}()

	deb := util.NewDebouncer(500 * time.Millisecond)
	for {
		select {
		case <-r.ctx.Done():
			deb.Stop()
			return
		case <-events:
			deb.Hit()
		case <-deb.C:
			deb.Fired()
			r.reprotectPeerEndpoints()
		}
	}
}

// reprotectPeerEndpoints re-adds peer endpoint host routes that are missing or no
// longer go through the current physical gateway.
func (r *darwinRouter) reprotectPeerEndpoints() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prevConfig == nil || r.ctx.Err() != nil {
		return
	}
	d4 := network.LookupPhysicalDefault4()
	d6 := network.LookupPhysicalDefault6()
	if d4.IfName != "" {
		r.physicalName, r.physicalIfIndex, r.savedGateway4 = d4.IfName, d4.IfIndex, d4.Gateway
	} else if d6.IfName != "" {
		r.physicalName, r.physicalIfIndex = d6.IfName, d6.IfIndex
	}
	if d6.IfName != "" {
		r.savedGateway6 = d6.Gateway
	}
	for _, p := range r.prevConfig.PeerEndpoints {
		if !endpointNeedsProtection(p, r.prevConfig.TunnelAddrs) {
			continue
		}
		addr := p.Addr()
		gw, live := r.savedGateway4, d4.IfName != ""
		if addr.Is6() {
			gw, live = r.savedGateway6, d6.IfName != ""
		}
		// With no physical network there is nothing to route through yet.
		if gw == "" || !live {
			continue
		}
		if rt, ok := r.lookupExactRoute(netip.PrefixFrom(addr, addr.BitLen())); ok && rt.gateway == gw {
			continue
		}
		_ = r.deleteHostRoute(addr)
		if err := r.addHostRoute(addr, gw); err != nil {
			log.Error(tag, "re-protect peer %v via %s: %v", addr, gw, err)
			continue
		}
		log.Debug(tag, "re-protected peer %v via %s", addr, gw)
	}
	r.reconcileRoutes()
	r.syncScopedDefaults(r.prevConfig)
}

type scopedDefault struct{ ifName, gw string }

// syncScopedDefaults keeps a default route scoped to the physical interface while the
// tunnel routes anything. A socket bound to an interface (IP_BOUND_IF), as the peer
// resolver's are, only finds routes scoped to it.
func (r *darwinRouter) syncScopedDefaults(c *router.Config) {
	var want4, want6 scopedDefault
	if len(c.Routes) > 0 {
		d4 := network.LookupPhysicalDefault4()
		want4 = scopedDefault{d4.IfName, d4.Gateway}
		if r.v6Available {
			d6 := network.LookupPhysicalDefault6()
			want6 = scopedDefault{d6.IfName, d6.Gateway}
		}
	}
	r.scoped4 = syncScopedDefault("inet", r.scoped4, want4)
	r.scoped6 = syncScopedDefault("inet6", r.scoped6, want6)
}

func plainIfName(n string) bool {
	if n == "" {
		return false
	}
	for _, c := range n {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// syncScopedDefault moves the scoped default this router added from have to want and
// returns what it owns afterwards.
func syncScopedDefault(inet string, have, want scopedDefault) scopedDefault {
	if !plainIfName(want.ifName) || want.gw == "" || strings.HasPrefix(want.gw, "link#") {
		want = scopedDefault{}
	}
	if have.ifName != "" && have != want {
		if out, err := exec.Command("route", "-q", "-n", "delete", "-"+inet, "default", "-ifscope", have.ifName).CombinedOutput(); err != nil {
			log.Debug(tag, "delete scoped default %s on %s: %v (%s)", inet, have.ifName, err, strings.TrimSpace(string(out)))
		}
		have = scopedDefault{}
	}
	if want.ifName == "" {
		return scopedDefault{}
	}
	out, err := exec.Command("route", "-q", "-n", "add", "-"+inet, "default", want.gw, "-ifscope", want.ifName).CombinedOutput()
	if strings.Contains(strings.ToLower(string(out)), "file exists") {
		// Ours from an earlier sync when have is set, macOS's own otherwise.
		return have
	}
	if err != nil {
		log.Error(tag, "add scoped default %s via %s on %s: %v (%s)", inet, want.gw, want.ifName, err, strings.TrimSpace(string(out)))
		return have
	}
	log.Debug(tag, "scoped default %s via %s on %s", inet, want.gw, want.ifName)
	return want
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

// syncForwarding keeps the forwarding rules on while the tunnel routes anything, see
// forwardAnchor.
func (r *darwinRouter) syncForwarding(c *router.Config) {
	if len(c.Routes) == 0 {
		PurgeForwarding()
		return
	}
	mtu := c.MTU
	if ifi, err := net.InterfaceByName(r.iface); err == nil {
		mtu = ifi.MTU
	}
	if err := loadForwardRules(r.iface, mtu); err != nil {
		log.Error(tag, "forwarding rules (continuing): %v", err)
	}
}

// tunnelServiceAddrs picks the addresses to publish as the primary service. Only a
// tunnel that owns both families qualifies. OverridePrimary takes over both, so a
// split tunnel would lose the physical network's other family.
func (r *darwinRouter) tunnelServiceAddrs(c *router.Config) (v4, v6 netip.Addr) {
	if !familyIsolated(c, true) || !familyIsolated(c, false) {
		return
	}
	for _, a := range c.TunnelAddrs {
		addr := a.Addr()
		switch {
		case addr.Is4() && !v4.IsValid() && familyUsable(c, true):
			v4 = addr
		case addr.Is6() && !v6.IsValid() && familyUsable(c, false) && r.v6Available:
			v6 = addr
		}
	}
	return
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
	msg := strings.ToLower(string(out))
	// route(8) exits 0 after "File exists", so the output is the only signal. Taking it as
	// added would later delete the LAN's own connected route on cleanup.
	if op == "add" && strings.Contains(msg, "file exists") {
		return errRouteExists
	}
	if err != nil {
		if op == "delete" && (strings.Contains(msg, "not in table") || strings.Contains(msg, "not exist")) {
			return nil
		}
		return fmt.Errorf("%v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
