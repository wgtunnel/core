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

func underlayFromDefaultRoute(ctx context.Context, wifiClient *wifi.Client) (NetworkInfo, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("route list: %w", err)
	}

	var mainPhysical, anyPhysical *netlink.Route
	sawTunDefault := false
	for i := range routes {
		r := &routes[i]
		if r.Dst != nil && !r.Dst.IP.Equal(net.IPv4zero) {
			continue
		}
		if r.LinkIndex == 0 {
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
		if anyPhysical == nil {
			anyPhysical = r
		}
		if r.Table == unix.RT_TABLE_MAIN || r.Table == 0 {
			mainPhysical = r
			break
		}
	}

	chosen := mainPhysical
	if chosen == nil {
		chosen = anyPhysical
	}
	if chosen == nil {
		if sawTunDefault {
			return NetworkInfo{}, errPhysicalDefaultHidden
		}
		return NetworkInfo{Type: NetworkDisconnected}, nil
	}

	return networkInfoFromLinkIndex(ctx, wifiClient, chosen.LinkIndex)
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
	info, err := underlayFromDefaultRoute(m.ctx, m.wifiClient)
	if errors.Is(err, errPhysicalDefaultHidden) {
		m.mu.RLock()
		prev := m.current
		m.mu.RUnlock()
		if prev.HasUsableUnderlay() {
			refreshed, rerr := networkInfoFromLinkIndex(m.ctx, m.wifiClient, int(prev.IfIndex))
			if rerr == nil {
				info = refreshed
			} else {
				info = prev
			}
			log.Debug(tag, "keeping physical underlay %s ifIndex=%d (tunnel owns default route)", info.InterfaceName, info.IfIndex)
		} else {
			info = NetworkInfo{Type: NetworkDisconnected}
		}
	} else if err != nil {
		info = NetworkInfo{Type: NetworkDisconnected}
	}

	m.mu.Lock()
	prev := m.current

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
