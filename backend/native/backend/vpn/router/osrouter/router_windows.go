// Copyright (c) 2026 Zane Schepke / WG Tunnel
//
// Portions of this file are derived from Tailscale
// Copyright (c) Tailscale Inc & contributors
// Licensed under the BSD 3-Clause License
// See NOTICE and LICENSES/BSD-3-Clause.txt in the project root

//go:build windows

package osrouter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/network"
	"github.com/wgtunnel/backend/resume"
	"github.com/wgtunnel/backend/util"
	"github.com/wgtunnel/backend/vpn/dns"
	"github.com/wgtunnel/backend/vpn/firewall"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall"
	"github.com/wgtunnel/backend/vpn/router"
	"go4.org/netipx"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tag = "Router"

// underlaySettle collapses the burst of route and interface notifications one
// network change produces into a single endpoint route refresh.
const underlaySettle = time.Second

type windowsRouter struct {
	// mu serializes Set with the endpoint route refresh that follows network changes.
	mu sync.Mutex

	iface       string
	fw          *osfirewall.WindowsFirewall
	prevConfig  *router.Config
	v6Available bool
	nativeTun   *tun.NativeTun
	luid        winipcfg.LUID
	rawLuid     uint64

	// privateStarted guards the one background NLA category pass per router.
	// The adapter profile is often published after Set returns.
	privateMu      sync.Mutex
	privateStarted bool

	originalGateway  netip.Addr
	originalGateway6 netip.Addr
	physicalLUID     winipcfg.LUID
	physicalLUID6    winipcfg.LUID

	// protectedEndpoints tracks the peer endpoint protection route currently installed for
	// each destination, so stale entries (peer removed, endpoint changed, gateway changed,
	// tunnel stopped) can be deleted instead of left behind in the routing table.
	protectedEndpoints map[netip.Prefix]protectedEndpointRoute

	physicalIfIndex uint32
	notifyHandle    *winipcfg.InterfaceChangeCallback
	routeHandle     *winipcfg.RouteChangeCallback
	underlayChanged chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
}

// protectedEndpointRoute is the interface/next-hop a peer endpoint protection route was
// actually installed with, so it can be deleted precisely later without a fresh lookup.
type protectedEndpointRoute struct {
	luid    winipcfg.LUID
	nextHop netip.Addr
}

func New(iface string, fw firewall.Firewall, tunnel tun.Device) (router.Router, error) {
	nativeTun := tunnel.(*tun.NativeTun)
	// get windows interface id
	rawLuid := nativeTun.LUID()

	ctx, cancel := context.WithCancel(context.Background())
	r := &windowsRouter{
		iface:              iface,
		fw:                 fw.(*osfirewall.WindowsFirewall),
		v6Available:        nettest.SupportsIPv6(),
		nativeTun:          nativeTun,
		rawLuid:            rawLuid,
		luid:               winipcfg.LUID(rawLuid),
		protectedEndpoints: make(map[netip.Prefix]protectedEndpointRoute),
		ctx:                ctx,
		cancel:             cancel,
		underlayChanged:    make(chan struct{}, 1),
	}
	go r.watchUnderlay()
	var err error
	if r.notifyHandle, err = winipcfg.RegisterInterfaceChangeCallback(r.onInterfaceChange); err != nil {
		log.Error(tag, "Interface change subscribe: %v", err)
	}
	if r.routeHandle, err = winipcfg.RegisterRouteChangeCallback(r.onRouteChange); err != nil {
		log.Error(tag, "Route change subscribe: %v", err)
	}
	return r, nil
}

func (r *windowsRouter) Set(c *router.Config) error {
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

	err := r.configureInterface(newC)
	if err != nil {
		log.Error(tag, "ConfigureInterface: %v", err)
		return err
	}

	// dns
	isPrevFull := prevC.HasAnyDefaultRoute()
	isNewFull := newC.HasAnyDefaultRoute()
	if !slices.Equal(newC.DNS, prevC.DNS) || !slices.Equal(newC.SearchDomains, prevC.SearchDomains) || isNewFull != isPrevFull {
		if err := dns.SetDNS(
			r.ctx,
			r.iface, // name, not LUID
			newC.DNS,
			newC.SearchDomains,
		); err != nil {
			return err
		}
	}

	if err := r.syncFirewallState(newC, familyIsolated(newC, true), familyIsolated(newC, false)); err != nil {
		return err
	}

	if err := flushCaches(); err != nil {
		log.Error(tag, "flush dns: %v", err)
	}

	r.prevConfig = newC.Clone()
	return nil
}

func (r *windowsRouter) syncFirewallState(newC *router.Config, requiresKSv4, requiresKSv6 bool) error {
	requiresKS := requiresKSv4 || requiresKSv6

	if !requiresKS && !r.fw.IsEnabled() {
		// not full tun and independent ks is not enabled, do nothing
		return nil
	} else if newC.Equal(&router.Config{}) && r.fw.IsEnabled() {
		if err := r.fw.RemoveTunnelRules(); err != nil {
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

	// If kill switch is active (independent or just enabled), always add tunnel bypasses
	if r.fw.IsEnabled() {
		log.Debug(tag, "FW enabled, adding tunnel bypass..")
		if err := r.fw.BypassTunnel(r.rawLuid, newC.ListenPort); err != nil {
			return fmt.Errorf("add firewall bypasses: %w", err)
		}
	}

	return nil
}

// getBit returns the value of the i-th bit
func getBit(addr netip.Addr, i int) bool {
	if i < 0 || i >= addr.BitLen() {
		return false
	}
	if addr.Is4() {
		b := addr.As4()
		byteIdx := i / 8
		bitIdx := 7 - (i % 8) // MSB first
		return (b[byteIdx] & (1 << bitIdx)) != 0
	}
	b := addr.As16()
	byteIdx := i / 8
	bitIdx := 7 - (i % 8)
	return (b[byteIdx] & (1 << bitIdx)) != 0
}

// onInterfaceChange catches an adapter connecting or disconnecting. A disconnected
// adapter can keep its default route, so the route callback alone misses it.
func (r *windowsRouter) onInterfaceChange(_ winipcfg.MibNotificationType, row *winipcfg.MibIPInterfaceRow) {
	if row != nil && row.InterfaceLUID == r.luid {
		return
	}
	r.signalUnderlayChange()
}

// onRouteChange catches a default route added, removed or given a new gateway on
// another adapter. Our own writes are split defaults on the tunnel and /32 or /128
// endpoint routes, so they never match.
func (r *windowsRouter) onRouteChange(_ winipcfg.MibNotificationType, row *winipcfg.MibIPforwardRow2) {
	if row == nil || row.DestinationPrefix.PrefixLength != 0 || row.InterfaceLUID == r.luid {
		return
	}
	r.signalUnderlayChange()
}

func (r *windowsRouter) signalUnderlayChange() {
	select {
	case r.underlayChanged <- struct{}{}:
	default:
	}
}

// watchUnderlay refreshes the endpoint routes once each burst of network changes
// settles. It only touches the endpoint routes, so it cannot retrigger itself the way
// a full configureInterface from the callback did.
func (r *windowsRouter) watchUnderlay() {
	deb := util.NewDebouncer(underlaySettle)
	for {
		select {
		case <-r.ctx.Done():
			deb.Stop()
			return
		case <-r.underlayChanged:
			deb.Hit()
		case <-deb.C:
			deb.Fired()
			r.refreshEndpointRoutes()
		}
	}
}

// refreshEndpointRoutes moves the endpoint routes to the current physical gateway.
// When the gateway changed, the sockets are rebound and new handshakes started, as
// the old path is gone.
func (r *windowsRouter) refreshEndpointRoutes() {
	r.mu.Lock()
	if r.ctx.Err() != nil || r.prevConfig == nil || len(r.prevConfig.PeerEndpoints) == 0 {
		r.mu.Unlock()
		return
	}
	moved := r.syncEndpointRoutes(r.prevConfig.PeerEndpoints)
	r.mu.Unlock()

	if moved {
		log.Debug(tag, "Physical gateway changed, rebinding tunnel sockets")
		resume.Rebind(tag)
	}
}

// setBit returns a new Addr with the i-th bit set to value
func setBit(addr netip.Addr, i int, value bool) netip.Addr {
	if addr.Is4() {
		b := addr.As4()
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		if value {
			b[byteIdx] |= 1 << bitIdx
		} else {
			b[byteIdx] &^= 1 << bitIdx
		}
		return netip.AddrFrom4(b)
	}
	b := addr.As16()
	byteIdx := i / 8
	bitIdx := 7 - (i % 8)
	if value {
		b[byteIdx] |= 1 << bitIdx
	} else {
		b[byteIdx] &^= 1 << bitIdx
	}
	return netip.AddrFrom16(b)
}

func (r *windowsRouter) Close() error {
	// Unregister network change callbacks
	if r.notifyHandle != nil {
		r.notifyHandle.Unregister()
		r.notifyHandle = nil
	}
	if r.routeHandle != nil {
		r.routeHandle.Unregister()
		r.routeHandle = nil
	}

	if r.prevConfig != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dns.RevertDNS(ctx, r.iface); err != nil {
			log.Error(tag, "revert DNS on close: %v", err)
		}
	}

	// Should be a no-op, can prevent windows firewall from tearing down
	if err := r.Set(nil); err != nil {
		log.Error(tag, "clear router config on close: %v", err)
	}

	r.cancel()

	log.Debug(tag, "Router closed")
	return nil
}

// configureInterface uses the split route specificity approach to prevent routing loops
func (r *windowsRouter) configureInterface(cfg *router.Config) error {
	iface, err := interfaceFromLUID(r.luid, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return fmt.Errorf("getting interface: %v", err)
	}

	// Private category is for LAN discovery on the tunnel adapter. NLA often
	// publishes the adapter after routes exist, so this must not block Set
	if cfg != nil && !cfg.Equal(&router.Config{}) {
		r.ensurePrivateNetwork()
	}

	r.syncEndpointRoutes(cfg.PeerEndpoints)

	ipif4, err := r.luid.IPInterface(windows.AF_INET)
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("getting AF_INET interface: %v", err)
	}
	ipif6, err := r.luid.IPInterface(windows.AF_INET6)
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("getting AF_INET6 interface: %v", err)
	}

	// Set up local tunnel addresses and gateways
	var localAddr4, localAddr6 netip.Addr
	var gatewayAddr4, gatewayAddr6 netip.Addr
	addresses := make([]netip.Prefix, 0, len(cfg.TunnelAddrs))
	for _, addr := range cfg.TunnelAddrs {
		if (addr.Addr().Is4() && ipif4 == nil) || (addr.Addr().Is6() && ipif6 == nil) {
			continue
		}
		addresses = append(addresses, addr)
		if addr.Addr().Is4() && !gatewayAddr4.IsValid() {
			localAddr4 = addr.Addr()
			gatewayAddr4 = netip.MustParseAddr("192.0.2.1")
		} else if addr.Addr().Is6() && !gatewayAddr6.IsValid() {
			localAddr6 = addr.Addr()
			gatewayAddr6 = netip.MustParseAddr("fc00::1")
		}
	}

	var routes []*routeData
	foundDefault4 := false
	foundDefault6 := false

	for _, route := range cfg.Routes {
		if (route.Addr().Is4() && ipif4 == nil) || (route.Addr().Is6() && ipif6 == nil) {
			continue
		}
		// Unsupported family is a /0 with no tun address, or the other family is a
		// usable full tunnel and this one has no address. Windows has no
		// blackhole route so the kill switch drops the family, including a
		// connected prefix that would otherwise beat a /1. A split prefix,
		// with no /0 on either family, still falls through and may use
		// dead:beef.
		if familyUnsupported(cfg, route.Addr().Is4()) {
			continue
		}

		// Initialize IPv6 gateway if needed
		if route.Addr().Is6() && !gatewayAddr6.IsValid() {
			ip := netip.MustParseAddr("fc00::dead:beef")
			addresses = append(addresses, netip.PrefixFrom(ip, ip.BitLen()))
			gatewayAddr6 = ip
		}

		var gateway, localAddr netip.Addr
		if route.Addr().Is4() {
			localAddr = localAddr4
			gateway = gatewayAddr4
		} else if route.Addr().Is6() {
			localAddr = localAddr6
			gateway = gatewayAddr6
		}

		// split route for higher specificity over default route
		if route.Bits() == 0 {
			var splits []netip.Prefix
			if route.Addr().Is4() {
				splits = []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/1"),
					netip.MustParsePrefix("128.0.0.0/1"),
				}
				foundDefault4 = true
			} else {
				splits = []netip.Prefix{
					netip.MustParsePrefix("::/1"),
					netip.MustParsePrefix("8000::/1"),
				}
				foundDefault6 = true
			}

			for _, p := range splits {
				routes = append(routes, &routeData{
					RouteData: winipcfg.RouteData{
						Destination: p,
						NextHop:     gateway,
						Metric:      0,
					},
				})
			}
			continue
		}

		// non-default routes
		if route.Addr().Unmap() == localAddr {
			continue
		}
		if route.IsSingleIP() {
			gateway = localAddr
		}

		routes = append(routes, &routeData{
			RouteData: winipcfg.RouteData{
				Destination: route,
				NextHop:     gateway,
				Metric:      0,
			},
		})
	}

	err = syncAddresses(iface, addresses)
	if err != nil {
		return fmt.Errorf("syncAddresses: %v", err)
	}

	slices.SortFunc(routes, (*routeData).Compare)

	var deduplicatedRoutes []*routeData
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Destination == routes[i-1].Destination {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, routes[i])
	}

	iface, err = interfaceFromLUID(r.luid, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return fmt.Errorf("getting interface after syncAddresses: %v", err)
	}

	var errAcc error
	err = syncRoutes(iface, deduplicatedRoutes, cfg.TunnelAddrs)
	if err != nil {
		errAcc = errors.Join(errAcc, err)
	}

	if ipif4 != nil {
		ipif4, err = r.luid.IPInterface(windows.AF_INET)
		if err != nil {
			return fmt.Errorf("getting AF_INET interface: %v", err)
		}
		if foundDefault4 {
			ipif4.UseAutomaticMetric = false
			ipif4.Metric = 0
		}
		ipif4.NLMTU = uint32(cfg.MTU)
		err = ipif4.Set()
		if err != nil {
			errAcc = errors.Join(errAcc, err)
		}
	}

	if ipif6 != nil {
		ipif6, err = r.luid.IPInterface(windows.AF_INET6)
		if err != nil {
			return fmt.Errorf("getting AF_INET6 interface: %v", err)
		}
		if foundDefault6 {
			ipif6.UseAutomaticMetric = false
			ipif6.Metric = 0
		}
		ipif6.NLMTU = uint32(cfg.MTU)
		ipif6.DadTransmits = 0
		ipif6.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		err = ipif6.Set()
		if err != nil {
			errAcc = errors.Join(errAcc, err)
		}
	}

	return errAcc
}

// syncEndpointRoutes points each public peer endpoint at the physical gateway with a
// metric 1 route, so the WireGuard socket stays out of the tunnel's split default
// routes. It reports whether the physical gateway or adapter changed since the last
// call while one is still usable.
func (r *windowsRouter) syncEndpointRoutes(endpoints []netip.Prefix) bool {
	prevGateway, prevLUID := r.originalGateway, r.physicalLUID
	prevGateway6, prevLUID6 := r.originalGateway6, r.physicalLUID6

	// Look up the physical gateway again on each call. v4 and v6 are looked up and tracked
	// separately.
	r.originalGateway = netip.Addr{}
	r.originalGateway6 = netip.Addr{}
	r.physicalLUID = 0
	r.physicalLUID6 = 0
	r.physicalIfIndex = 0
	// Pick the default route Windows would use without the tunnel, skipping
	// adapters that are down or disconnected. A disconnected Ethernet adapter
	// with a static gateway keeps its default route, and taking the first one
	// in the table sent the endpoint route there.
	if pr, ok, err := network.PhysicalDefaultRoute(windows.AF_INET); err != nil {
		log.Error(tag, "Finding physical IPv4 default route: %v", err)
	} else if ok {
		r.originalGateway, r.physicalLUID, r.physicalIfIndex = pr.NextHop, pr.LUID, pr.IfIndex
		log.Debug(tag, "Detected physical IPv4 gateway %v (LUID %d, Index %d) for peer endpoint protection", r.originalGateway, r.physicalLUID, r.physicalIfIndex)
	}
	if pr, ok, err := network.PhysicalDefaultRoute(windows.AF_INET6); err != nil {
		log.Error(tag, "Finding physical IPv6 default route: %v", err)
	} else if ok {
		r.originalGateway6, r.physicalLUID6 = pr.NextHop, pr.LUID
		log.Debug(tag, "Detected physical IPv6 gateway %v (LUID %d) for peer endpoint protection", r.originalGateway6, r.physicalLUID6)
	}

	// Protect peer public endpoints from the routing loop by adding a route via the physical
	// interface with metric 1, taking priority over the tunnel's split-default routes. Routes
	// are reconciled against what's currently installed so peers that are removed, change
	// endpoint, or see their physical gateway change don't leave a stale route behind and so
	// that closing the tunnel cleans all of them up.
	wantedEndpoints := make(map[netip.Prefix]bool, len(endpoints))
	for _, prefix := range endpoints {
		if !prefix.IsValid() || prefix.Addr().IsPrivate() || prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		wantedEndpoints[prefix] = true

		gateway, physicalLUID := r.originalGateway, r.physicalLUID
		if prefix.Addr().Is6() {
			gateway, physicalLUID = r.originalGateway6, r.physicalLUID6
		}
		if !gateway.IsValid() || physicalLUID == 0 {
			// A route via the tunnel itself would loop the endpoint into the
			// tunnel. Leave any route already installed for it in place.
			log.Error(tag, "No usable physical gateway to protect peer endpoint %v", prefix.Addr())
			continue
		}
		wantLUID, wantNextHop := physicalLUID, gateway

		if existing, ok := r.protectedEndpoints[prefix]; ok {
			if existing.luid == wantLUID && existing.nextHop == wantNextHop {
				continue // already protected correctly
			}
			if err := existing.luid.DeleteRoute(prefix, existing.nextHop); err != nil {
				log.Debug(tag, "Failed to remove outdated peer endpoint route %v: %v", prefix.Addr(), err)
			}
			delete(r.protectedEndpoints, prefix)
		}

		if err := wantLUID.AddRoute(prefix, wantNextHop, 1); err != nil {
			if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				log.Error(tag, "Failed to add peer endpoint route %v: %v", prefix.Addr(), err)
				continue
			}
			// The same route is already there, likely left by a session that
			// did not clean up. Track it so it is removed with the tunnel.
			log.Debug(tag, "Peer endpoint route %v already present, tracking it", prefix.Addr())
		} else {
			log.Debug(tag, "Added protecting route for peer endpoint %v", prefix.Addr())
		}
		r.protectedEndpoints[prefix] = protectedEndpointRoute{luid: wantLUID, nextHop: wantNextHop}
	}
	for prefix, pe := range r.protectedEndpoints {
		if wantedEndpoints[prefix] {
			continue
		}
		if err := pe.luid.DeleteRoute(prefix, pe.nextHop); err != nil {
			log.Debug(tag, "Failed to remove stale peer endpoint route %v: %v", prefix.Addr(), err)
		}
		delete(r.protectedEndpoints, prefix)
	}

	moved4 := r.originalGateway.IsValid() && (r.originalGateway != prevGateway || r.physicalLUID != prevLUID)
	moved6 := r.originalGateway6.IsValid() && (r.originalGateway6 != prevGateway6 || r.physicalLUID6 != prevLUID6)
	return moved4 || moved6
}

func (r *windowsRouter) GetPhysicalInterfaceIndex() uint32 {
	return r.physicalIfIndex
}

func isIPv6LinkLocal(a netip.Prefix) bool {
	return a.Addr().Is6() && a.Addr().IsLinkLocalUnicast()
}

// ipAdapterUnicastAddressToPrefix converts windows IpAdapterUnicastAddress to netip.Prefix
func ipAdapterUnicastAddressToPrefix(u *windows.IpAdapterUnicastAddress) netip.Prefix {
	ip, _ := netip.AddrFromSlice(u.Address.IP())
	return netip.PrefixFrom(ip.Unmap(), int(u.OnLinkPrefixLength))
}

// unicastIPNets returns all unicast net.IPNet for ifc interface.
func unicastIPNets(ifc *winipcfg.IPAdapterAddresses) []netip.Prefix {
	var nets []netip.Prefix
	for addr := ifc.FirstUnicastAddress; addr != nil; addr = addr.Next {
		nets = append(nets, ipAdapterUnicastAddressToPrefix(addr))
	}
	return nets
}

func syncAddresses(ifc *winipcfg.IPAdapterAddresses, want []netip.Prefix) error {
	got := unicastIPNets(ifc)
	add, del := deltaNets(got, want)
	var erracc error
	ll := make([]netip.Prefix, 0)
	for _, a := range del {
		if isIPv6LinkLocal(a) {
			ll = append(ll, a)
			continue
		}
		err := ifc.LUID.DeleteIPAddress(a)
		if err != nil {
			erracc = errors.Join(erracc, fmt.Errorf("deleting IP %q: %v", a, err))
		}
	}
	for _, a := range add {
		err := ifc.LUID.AddIPAddress(a)
		if err != nil {
			erracc = errors.Join(erracc, fmt.Errorf("adding IP %q: %v", a, err))
		}
	}
	for _, a := range ll {
		mib, err := ifc.LUID.IPAddress(a.Addr())
		if err != nil {
			erracc = errors.Join(erracc, fmt.Errorf("setting skip-as-source on IP %q: unable to retrieve MIB: %v", a, err))
			continue
		}
		if !mib.SkipAsSource {
			mib.SkipAsSource = true
			if err := mib.Set(); err != nil {
				erracc = errors.Join(erracc, fmt.Errorf("setting skip-as-source on IP %q: unable to set MIB: %v", a, err))
			}
		}
	}
	return erracc
}

// routeData wraps winipcfg.RouteData with an additional field that permits
// caching of the associated MibIPForwardRow2; by keeping it around, we can
// avoid unnecessary lookups of information that we already have.
type routeData struct {
	winipcfg.RouteData
	Row *winipcfg.MibIPforwardRow2
}

func (rd *routeData) Compare(other *routeData) int {
	v := rd.Destination.Addr().Compare(other.Destination.Addr())
	if v != 0 {
		return v
	}
	b1, b2 := rd.Destination.Bits(), other.Destination.Bits()
	if b1 != b2 {
		if b1 > b2 {
			return -1
		}
		return 1
	}
	v = rd.NextHop.Compare(other.NextHop)
	if v != 0 {
		return v
	}
	if rd.Metric < other.Metric {
		return -1
	} else if rd.Metric > other.Metric {
		return 1
	}
	return 0
}

func deltaRouteData(a, b []*routeData) (add, del []*routeData) {
	add = make([]*routeData, 0, len(b))
	del = make([]*routeData, 0, len(a))
	slices.SortFunc(a, (*routeData).Compare)
	slices.SortFunc(b, (*routeData).Compare)

	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch a[i].Compare(b[j]) {
		case -1:
			del = append(del, a[i])
			i++
		case 0:
			i++
			j++
		case 1:
			add = append(add, b[j])
			j++
		}
	}
	del = append(del, a[i:]...)
	add = append(add, b[j:]...)
	return
}

// getInterfaceRoutes returns all the interface's routes.
func getInterfaceRoutes(ifc *winipcfg.IPAdapterAddresses, family winipcfg.AddressFamily) (matches []*winipcfg.MibIPforwardRow2, err error) {
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].InterfaceLUID == ifc.LUID {
			matches = append(matches, &routes[i])
		}
	}
	return
}

func getAllInterfaceRoutes(ifc *winipcfg.IPAdapterAddresses) ([]*routeData, error) {
	routes4, err := getInterfaceRoutes(ifc, windows.AF_INET)
	if err != nil {
		return nil, err
	}

	routes6, err := getInterfaceRoutes(ifc, windows.AF_INET6)
	if err != nil {
		// TODO: what if v6 unavailable?
		return nil, err
	}

	rd := make([]*routeData, 0, len(routes4)+len(routes6))
	for _, r := range routes4 {
		rd = append(rd, &routeData{
			RouteData: winipcfg.RouteData{
				Destination: r.DestinationPrefix.Prefix(),
				NextHop:     r.NextHop.Addr(),
				Metric:      r.Metric,
			},
			Row: r,
		})
	}
	for _, r := range routes6 {
		rd = append(rd, &routeData{
			RouteData: winipcfg.RouteData{
				Destination: r.DestinationPrefix.Prefix(),
				NextHop:     r.NextHop.Addr(),
				Metric:      r.Metric,
			},
			Row: r,
		})
	}
	return rd, nil
}

func filterRoutes(routes []*routeData, dontDelete []netip.Prefix) []*routeData {
	ddm := make(map[netip.Prefix]bool)
	for _, dd := range dontDelete {
		ddm[dd] = true
	}
	for _, r := range routes {
		nr := r.Destination
		if !nr.IsValid() {
			continue
		}
		if nr.IsSingleIP() {
			continue
		}
		lastIP := netipx.RangeOfPrefix(nr).To()
		ddm[netip.PrefixFrom(lastIP, lastIP.BitLen())] = true
	}
	filtered := make([]*routeData, 0, len(routes))
	for _, r := range routes {
		rr := r.Destination
		if rr.IsValid() && ddm[rr] {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// syncRoutes incrementally sets multiples routes on an interface.
// This avoids a full ifc.FlushRoutes call.
// dontDelete is a list of interface address routes that the
// synchronization logic should never delete.
func syncRoutes(ifc *winipcfg.IPAdapterAddresses, want []*routeData, dontDelete []netip.Prefix) error {
	existingRoutes, err := getAllInterfaceRoutes(ifc)
	if err != nil {
		return err
	}
	got := filterRoutes(existingRoutes, dontDelete)

	add, del := deltaRouteData(got, want)

	var errs []error
	for _, a := range del {
		var err error
		if a.Row == nil {
			// DeleteRoute requires a routing table lookup, so only do that if
			// a does not already have the row.
			err = ifc.LUID.DeleteRoute(a.Destination, a.NextHop)
		} else {
			// delete the row directly.
			err = a.Row.Delete()
		}
		if err != nil {
			dstStr := a.Destination.String()
			if dstStr == "169.254.255.255/32" {
				// Issue 785 (Tailscale). Ignore these routes
				// failing to delete. Harmless.
				continue
			}
			errs = append(errs, fmt.Errorf("deleting route %v: %v", dstStr, err))
		}
	}

	for _, a := range add {
		err := ifc.LUID.AddRoute(a.Destination, a.NextHop, a.Metric)
		if err != nil {
			errs = append(errs, fmt.Errorf("adding route %v: %v", &a.Destination, err))
		}
	}

	return errors.Join(errs...)
}

// deltaNets returns the changes to turn a into b.
func deltaNets(a, b []netip.Prefix) (add, del []netip.Prefix) {
	add = make([]netip.Prefix, 0, len(b))
	del = make([]netip.Prefix, 0, len(a))
	sortNets(a)
	sortNets(b)

	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch netCompare(a[i], b[j]) {
		case -1:
			del = append(del, a[i])
			i++
		case 0:
			i++
			j++
		case 1:
			add = append(add, b[j])
			j++
		default:
			panic("unexpected compare result")
		}
	}
	del = append(del, a[i:]...)
	add = append(add, b[j:]...)
	return
}

func netCompare(a, b netip.Prefix) int {
	aip, bip := a.Addr().Unmap(), b.Addr().Unmap()
	v := aip.Compare(bip)
	if v != 0 {
		return v
	}
	if a.Bits() == b.Bits() {
		return 0
	}
	if a.Bits() > b.Bits() {
		return -1
	}
	return 1
}

func sortNets(s []netip.Prefix) {
	sort.Slice(s, func(i, j int) bool {
		return netCompare(s[i], s[j]) < 0
	})
}

// interfaceFromLUID returns IPAdapterAddresses with specified LUID.
func interfaceFromLUID(luid winipcfg.LUID, flags winipcfg.GAAFlags) (*winipcfg.IPAdapterAddresses, error) {
	addresses, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, flags)
	if err != nil {
		return nil, err
	}
	for _, addr := range addresses {
		if addr.LUID == luid {
			return addr, nil
		}
	}
	return nil, fmt.Errorf("interfaceFromLUID: interface with LUID %v not found", luid)
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushCaches() error {
	if err := procDnsFlushResolverCache.Find(); err != nil {
		return err
	}
	r, _, err := procDnsFlushResolverCache.Call()
	if r == 0 {
		if err != nil && err != windows.ERROR_SUCCESS {
			return fmt.Errorf("DnsFlushResolverCache: %w", err)
		}
		return errors.New("DnsFlushResolverCache failed")
	}
	return nil
}
