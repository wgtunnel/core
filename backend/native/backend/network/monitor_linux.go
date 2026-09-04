//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/wifi"
	"github.com/vishvananda/netlink"
	"github.com/wgtunnel/backend/constants"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/util"
	"github.com/wgtunnel/backend/vpn/dns"
	"golang.org/x/sys/unix"
)

const (
	debounceInterval = 200 * time.Millisecond
	tag              = "NetworkMonitor"
)

type linuxMonitor struct {
	started   bool
	mu        sync.RWMutex
	current   NetworkInfo
	listeners []func(NetworkInfo)

	stopOnce   sync.Once
	stopCh     chan struct{}
	wifiClient *wifi.Client

	ctx    context.Context
	cancel context.CancelFunc
}

func NewMonitor() Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &linuxMonitor{
		stopCh: make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (m *linuxMonitor) Current() NetworkInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *linuxMonitor) Notify(fn func(NetworkInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, fn)
}

func (m *linuxMonitor) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()
	if client, err := wifi.New(); err == nil {
		m.wifiClient = client
	} else {
		// Continue without nl80211
		m.wifiClient = nil
	}
	// Initial snapshot
	m.refresh()

	routeCh := make(chan netlink.RouteUpdate, 16)
	linkCh := make(chan netlink.LinkUpdate, 16)
	addrCh := make(chan netlink.AddrUpdate, 16)

	// done is closed to stop subscriptions
	done := make(chan struct{})

	if err := netlink.RouteSubscribe(routeCh, done); err != nil {
		return fmt.Errorf("route subscribe: %w", err)
	}
	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		close(done)
		return fmt.Errorf("link subscribe: %w", err)
	}
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		close(done)
		return fmt.Errorf("addr subscribe: %w", err)
	}

	go func() {
		defer close(done) // stops all netlink subscriptions

		deb := util.NewDebouncer(debounceInterval)

		for {
			select {
			case <-m.stopCh:
				deb.Stop()
				return

			case <-routeCh:
				deb.Hit()
			case <-linkCh:
				deb.Hit()
			case <-addrCh:
				deb.Hit()

			case <-deb.C:
				deb.Fired()
				m.refresh()
			}
		}
	}()

	return nil
}

func (m *linuxMonitor) Stop() {
	m.stopOnce.Do(func() {
		m.cancel() // cancel in-flight ReadUnderlayDNS / D-Bus
		close(m.stopCh)
		if m.wifiClient != nil {
			_ = m.wifiClient.Close()
			m.wifiClient = nil
		}
	})
}

func isWifiName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "wlan") ||
		strings.HasPrefix(n, "wifi") ||
		strings.HasPrefix(n, "wl")
}

func isTunnelIface(name string) bool {
	return strings.HasPrefix(name, constants.TunPrefix) ||
		strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "wg")
}

func isDefaultDst(dst *net.IPNet, family int) bool {
	if dst == nil {
		return true
	}
	if family == netlink.FAMILY_V4 {
		return dst.IP.Equal(net.IPv4zero)
	}
	return dst.IP.IsUnspecified()
}

func underlayFromDefaultRoute(ctx context.Context, wifiClient *wifi.Client) (NetworkInfo, error) {
	if info, err := kernelChosenUnderlay(ctx, wifiClient, netlink.FAMILY_V4); err == nil {
		return info, nil
	} else if errors.Is(err, errPhysicalDefaultHidden) {
		return NetworkInfo{}, err
	}
	if info, err := kernelChosenUnderlay(ctx, wifiClient, netlink.FAMILY_V6); err == nil {
		return info, nil
	} else if errors.Is(err, errPhysicalDefaultHidden) {
		return NetworkInfo{}, err
	}

	info, err := defaultRouteUnderlay(ctx, wifiClient, netlink.FAMILY_V4)
	if err == nil && info.Type != NetworkDisconnected {
		return info, nil
	}
	v6, v6err := defaultRouteUnderlay(ctx, wifiClient, netlink.FAMILY_V6)
	if v6err == nil && v6.Type != NetworkDisconnected {
		return v6, nil
	}
	if errors.Is(err, errPhysicalDefaultHidden) || errors.Is(v6err, errPhysicalDefaultHidden) {
		return NetworkInfo{}, errPhysicalDefaultHidden
	}
	if err != nil {
		return NetworkInfo{}, err
	}
	return info, nil
}

func kernelChosenUnderlay(
	ctx context.Context,
	wifiClient *wifi.Client,
	family int,
) (NetworkInfo, error) {
	var dst net.IP
	if family == netlink.FAMILY_V4 {
		dst = net.IPv4(1, 1, 1, 1)
	} else {
		dst = net.ParseIP("2606:4700:4700::1111")
	}
	routes, err := netlink.RouteGet(dst)
	if err != nil || len(routes) == 0 {
		if err == nil {
			err = fmt.Errorf("no route")
		}
		return NetworkInfo{}, err
	}
	index := routes[0].LinkIndex
	if index == 0 {
		return NetworkInfo{}, fmt.Errorf("no oif")
	}
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return NetworkInfo{}, err
	}
	name := link.Attrs().Name
	if isTunnelIface(name) {
		return NetworkInfo{}, errPhysicalDefaultHidden
	}
	log.Debug(tag, "kernel underlay family=%d iface=%s ifIndex=%d metric=%d", family, name, index, routes[0].Priority)
	return networkInfoFromLinkIndex(ctx, wifiClient, index)
}

type defaultRouteCandidate struct {
	route netlink.Route
	name  string
	main  bool
}

func defaultRouteUnderlay(ctx context.Context, wifiClient *wifi.Client, family int) (NetworkInfo, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{}, 0)
	if err != nil {
		routes, err = netlink.RouteList(nil, family)
		if err != nil {
			return NetworkInfo{}, fmt.Errorf("route list: %w", err)
		}
	}

	var candidates []defaultRouteCandidate
	sawTunDefault := false
	for i := range routes {
		r := routes[i]
		if r.LinkIndex == 0 || !isDefaultDst(r.Dst, family) {
			continue
		}
		if r.Type != 0 && r.Type != unix.RTN_UNICAST {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			continue
		}
		name := link.Attrs().Name
		if isTunnelIface(name) {
			sawTunDefault = true
			continue
		}
		candidates = append(
			candidates,
			defaultRouteCandidate{
				route: r,
				name:  name,
				main:  r.Table == unix.RT_TABLE_MAIN || r.Table == 0,
			},
		)
	}

	if len(candidates) == 0 {
		if sawTunDefault {
			return NetworkInfo{}, errPhysicalDefaultHidden
		}
		return NetworkInfo{Type: NetworkDisconnected}, nil
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if betterDefaultRoute(c, best) {
			best = c
		}
	}
	log.Debug(
		tag,
		"listed underlay family=%d iface=%s ifIndex=%d metric=%d table=%d candidates=%d",
		family,
		best.name,
		best.route.LinkIndex,
		best.route.Priority,
		best.route.Table,
		len(candidates),
	)
	return networkInfoFromLinkIndex(ctx, wifiClient, best.route.LinkIndex)
}

func betterDefaultRoute(a, b defaultRouteCandidate) bool {
	if a.route.Priority != b.route.Priority {
		return a.route.Priority < b.route.Priority
	}
	if a.main != b.main {
		return a.main
	}
	return preferLinkIndex(a.route.LinkIndex, b.route.LinkIndex)
}

func preferLinkIndex(a, b int) bool {
	la, aerr := netlink.LinkByIndex(a)
	lb, berr := netlink.LinkByIndex(b)
	if aerr != nil || berr != nil {
		return false
	}
	return linkPreference(la) > linkPreference(lb)
}

func linkPreference(link netlink.Link) int {
	name := link.Attrs().Name
	switch {
	case strings.HasPrefix(name, "eth"), strings.HasPrefix(name, "en"):
		return 3
	case isWifiName(name):
		return 2
	default:
		return 1
	}
}

func bestPhysicalUnderlay(ctx context.Context, wifiClient *wifi.Client, prev NetworkInfo) (NetworkInfo, error) {
	if prev.HasUsableUnderlay() {
		refreshed, err := networkInfoFromLinkIndex(ctx, wifiClient, int(prev.IfIndex))
		if err == nil && (refreshed.HasIPv4 || refreshed.HasIPv6) {
			if link, lerr := netlink.LinkByIndex(int(prev.IfIndex)); lerr == nil {
				if link.Attrs().Flags&net.FlagUp != 0 {
					return refreshed, nil
				}
			}
		}
	}

	links, err := netlink.LinkList()
	if err != nil {
		return NetworkInfo{Type: NetworkDisconnected}, err
	}

	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Flags&net.FlagUp == 0 {
			continue
		}
		name := attrs.Name
		if name == "lo" || isTunnelIface(name) {
			continue
		}
		info, ierr := networkInfoFromLinkIndex(ctx, wifiClient, attrs.Index)
		if ierr != nil || (!info.HasIPv4 && !info.HasIPv6) {
			continue
		}
		return info, nil
	}
	return NetworkInfo{Type: NetworkDisconnected}, nil
}

func networkInfoFromLinkIndex(ctx context.Context, client *wifi.Client, ifIndex int) (NetworkInfo, error) {
	link, err := netlink.LinkByIndex(ifIndex)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("link by index %d: %w", ifIndex, err)
	}

	attrs := link.Attrs()
	info := NetworkInfo{
		InterfaceName: attrs.Name,
		IfIndex:       uint32(attrs.Index),
	}

	// Addresses
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return info, fmt.Errorf("addr list: %w", err)
	}
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			info.HasIPv4 = true
		} else if ip.To16() != nil {
			info.HasIPv6 = true
		}
	}

	// Attempt to get Wi-Fi details
	ssid, bssid, wireless, werr := wifiInfoForInterface(client, info.IfIndex, info.InterfaceName)
	if werr != nil {
		log.Debug(tag, "wifi info ifIndex=%d iface=%s: %v", info.IfIndex, info.InterfaceName, werr)
		wireless = false
	}

	// If nl80211 failed/unavailable, guess from interface name
	if !wireless && isWifiName(info.InterfaceName) {
		wireless = true
	}

	servers, derr := dns.ReadUnderlayDNS(ctx, info.IfIndex, info.InterfaceName)
	if derr != nil {
		log.Debug(tag, "underlay dns ifIndex=%d iface=%s: %v", info.IfIndex, info.InterfaceName, derr)
	} else {
		info.DNSServers = servers
	}

	info.Type = classifyLink(link, wireless)

	if wireless {
		if ssid == "" {
			info.SSID = UnknownSSID
		} else {
			info.SSID = ssid
		}
		if bssid == "" {
			info.BSSID = UnknownBSSID
		} else {
			info.BSSID = bssid
		}
	}

	return info, nil
}

func classifyLink(link netlink.Link, wireless bool) NetworkType {
	if wireless {
		return NetworkWifi
	}

	name := link.Attrs().Name
	switch {
	case strings.HasPrefix(name, "eth"),
		strings.HasPrefix(name, "en"):
		return NetworkEthernet
	default:
		return NetworkOther
	}
}

func (m *linuxMonitor) refresh() {
	if err := m.ctx.Err(); err != nil {
		return
	}
	m.mu.RLock()
	prev := m.current
	m.mu.RUnlock()

	info, err := underlayFromDefaultRoute(m.ctx, m.wifiClient)
	if errors.Is(err, errPhysicalDefaultHidden) {
		fallback, ferr := bestPhysicalUnderlay(m.ctx, m.wifiClient, prev)
		if ferr != nil {
			info = NetworkInfo{Type: NetworkDisconnected}
		} else {
			info = fallback
		}
		log.Debug(tag, "tunnel owns default route; underlay %s ifIndex=%d type=%d", info.InterfaceName, info.IfIndex, info.Type)
	} else if err != nil {
		info = NetworkInfo{Type: NetworkDisconnected}
	}

	m.mu.Lock()

	// Keep DNS if same underlay and new list empty
	if info.IfIndex != 0 &&
		info.IfIndex == prev.IfIndex &&
		len(info.DNSServers) == 0 &&
		len(prev.DNSServers) > 0 {
		info.DNSServers = append([]string(nil), prev.DNSServers...)
	}

	// Keep SSID/BSSID if same underlay and new read is only placeholders
	if info.IfIndex != 0 && info.IfIndex == prev.IfIndex && info.Type == NetworkWifi {
		if info.SSID == UnknownSSID &&
			prev.SSID != "" && prev.SSID != UnknownSSID {
			info.SSID = prev.SSID
		}
		if info.BSSID == UnknownBSSID &&
			prev.BSSID != "" && prev.BSSID != UnknownBSSID {
			info.BSSID = prev.BSSID
		}
	}

	if prev.Equal(info) {
		m.mu.Unlock()
		return
	}

	m.current = info
	listeners := append([]func(NetworkInfo){}, m.listeners...)
	m.mu.Unlock()

	for _, fn := range listeners {
		fn(info)
	}
}
