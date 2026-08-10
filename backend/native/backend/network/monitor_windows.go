//go:build windows

package network

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wgtunnel/backend/constants"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/util"
	"github.com/wgtunnel/backend/vpn/dns"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	debounceInterval = 200 * time.Millisecond
	tag              = "NetworkMonitor"
)

type windowsMonitor struct {
	started   bool
	mu        sync.RWMutex
	current   NetworkInfo
	listeners []func(NetworkInfo)

	stopOnce   sync.Once
	stopCh     chan struct{}
	refreshReq chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	unregs []winipcfg.ChangeCallback
}

func NewMonitor() Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &windowsMonitor{
		stopCh:     make(chan struct{}),
		refreshReq: make(chan struct{}, 1),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (m *windowsMonitor) Current() NetworkInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *windowsMonitor) Notify(fn func(NetworkInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, fn)
}

func (m *windowsMonitor) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	m.refresh()

	routeCb, err := winipcfg.RegisterRouteChangeCallback(func(
		_ winipcfg.MibNotificationType,
		_ *winipcfg.MibIPforwardRow2,
	) {
		m.pingRefresh()
	})
	if err != nil {
		return fmt.Errorf("route subscribe: %w", err)
	}

	ifaceCb, err := winipcfg.RegisterInterfaceChangeCallback(func(
		_ winipcfg.MibNotificationType,
		_ *winipcfg.MibIPInterfaceRow,
	) {
		m.pingRefresh()
	})
	if err != nil {
		_ = routeCb.Unregister()
		return fmt.Errorf("interface subscribe: %w", err)
	}

	addrCb, err := winipcfg.RegisterUnicastAddressChangeCallback(func(
		_ winipcfg.MibNotificationType,
		_ *winipcfg.MibUnicastIPAddressRow,
	) {
		m.pingRefresh()
	})
	if err != nil {
		_ = routeCb.Unregister()
		_ = ifaceCb.Unregister()
		return fmt.Errorf("address subscribe: %w", err)
	}

	m.mu.Lock()
	m.unregs = []winipcfg.ChangeCallback{routeCb, ifaceCb, addrCb}
	m.mu.Unlock()

	go m.loop()
	return nil
}

func (m *windowsMonitor) pingRefresh() {
	select {
	case m.refreshReq <- struct{}{}:
	default:
	}
}

func (m *windowsMonitor) loop() {
	deb := util.NewDebouncer(debounceInterval)
	for {
		select {
		case <-m.stopCh:
			deb.Stop()
			return
		case <-m.refreshReq:
			deb.Hit()
		case <-deb.C:
			deb.Fired()
			m.refresh()
		}
	}
}

func (m *windowsMonitor) Stop() {
	m.stopOnce.Do(func() {
		m.cancel()
		close(m.stopCh)

		m.mu.Lock()
		unregs := m.unregs
		m.unregs = nil
		m.mu.Unlock()

		for _, u := range unregs {
			_ = u.Unregister()
		}
	})
}

func (m *windowsMonitor) refresh() {
	if err := m.ctx.Err(); err != nil {
		return
	}

	info, err := underlayFromDefaultRoute(m.ctx)
	if err != nil {
		log.Debug(tag, "underlay refresh: %v", err)
		info = NetworkInfo{Type: NetworkDisconnected}
	}

	m.mu.Lock()
	prev := m.current

	// Last known DNS on same underlay
	if info.IfIndex != 0 &&
		info.IfIndex == prev.IfIndex &&
		len(info.DNSServers) == 0 &&
		len(prev.DNSServers) > 0 {
		info.DNSServers = append([]string(nil), prev.DNSServers...)
	}

	// Keep last good SSID/BSSID
	if info.IfIndex != 0 && info.IfIndex == prev.IfIndex && info.Type == NetworkWifi {
		if info.SSID == "" && prev.SSID != "" {
			info.SSID = prev.SSID
		}
		if info.BSSID == "" && prev.BSSID != "" {
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

func underlayFromDefaultRoute(ctx context.Context) (NetworkInfo, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("forward table: %w", err)
	}

	var best *winipcfg.MibIPforwardRow2
	var bestMetric uint32 = ^uint32(0)

	for i := range rows {
		r := &rows[i]
		pref := r.DestinationPrefix.Prefix()
		if !pref.IsValid() || !pref.Addr().Is4() || pref.Bits() != 0 {
			continue
		}
		if isTunnelLUID(r.InterfaceLUID) {
			continue
		}
		if r.Metric < bestMetric {
			bestMetric = r.Metric
			best = r
		}
	}

	if best == nil {
		return NetworkInfo{Type: NetworkDisconnected}, nil
	}
	return networkInfoFromLUID(ctx, best.InterfaceLUID, best.InterfaceIndex)
}

func networkInfoFromLUID(ctx context.Context, luid winipcfg.LUID, ifIndex uint32) (NetworkInfo, error) {
	addrs, err := winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return NetworkInfo{}, err
	}

	var a *winipcfg.IPAdapterAddresses
	for _, x := range addrs {
		if x.LUID == luid || (ifIndex != 0 && x.IfIndex == ifIndex) {
			a = x
			break
		}
	}
	if a == nil {
		return NetworkInfo{Type: NetworkDisconnected}, nil
	}

	info := NetworkInfo{
		InterfaceName: a.FriendlyName(),
		IfIndex:       a.IfIndex,
		Type:          classifyIfType(a.IfType),
	}
	if info.InterfaceName == "" {
		info.InterfaceName = a.AdapterName()
	}

	for u := a.FirstUnicastAddress; u != nil; u = u.Next {
		ip := u.Address.IP()
		if len(ip) == 0 {
			continue
		}
		if ip.To4() != nil {
			info.HasIPv4 = true
		} else {
			info.HasIPv6 = true
		}
	}

	if info.Type == NetworkWifi {
		ssid, bssid, wireless, werr := wifiInfoForInterface(info.IfIndex, info.InterfaceName)
		if werr != nil {
			log.Debug(tag, "wifi info ifIndex=%d iface=%s: %v",
				info.IfIndex, info.InterfaceName, werr)
		}
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
		} else {
			// Unable to get Wi-Fi details, use placeholders
			info.SSID = UnknownSSID
			info.BSSID = UnknownBSSID
		}
	}

	servers, err := dns.ReadUnderlayDNS(ctx, info.IfIndex, info.InterfaceName)
	if err != nil {
		log.Debug(tag, "underlay dns ifIndex=%d iface=%s: %v",
			info.IfIndex, info.InterfaceName, err)
	} else {
		info.DNSServers = servers
	}

	return info, nil
}

func classifyIfType(t winipcfg.IfType) NetworkType {
	switch t {
	case winipcfg.IfTypeIEEE80211:
		return NetworkWifi
	case winipcfg.IfTypeEthernetCSMACD,
		winipcfg.IfTypeGigabitethernet,
		winipcfg.IfTypeFastether:
		return NetworkEthernet
	default:
		return NetworkOther
	}
}

func isTunnelLUID(luid winipcfg.LUID) bool {
	addrs, err := winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.LUID == luid {
			return isTunnelAdapter(a)
		}
	}
	return false
}

func isTunnelAdapter(a *winipcfg.IPAdapterAddresses) bool {
	name := strings.ToLower(a.FriendlyName() + " " + a.AdapterName())
	prefix := strings.ToLower(constants.TunPrefix)
	return strings.Contains(name, prefix) ||
		strings.Contains(name, "wgtun") ||
		strings.Contains(name, "wintun") ||
		strings.Contains(name, "wireguard") ||
		a.IfType == winipcfg.IfTypeTunnel
}
