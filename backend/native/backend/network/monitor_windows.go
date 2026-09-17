//go:build windows

package network

import (
	"context"
	"errors"
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

	m.mu.RLock()
	prev := m.current
	m.mu.RUnlock()

	info, err := underlayFromDefaultRoute(m.ctx)
	if errors.Is(err, errPhysicalDefaultHidden) {
		fallback, ferr := bestPhysicalUnderlay(m.ctx, prev)
		if ferr != nil {
			info = NetworkInfo{Type: NetworkDisconnected}
		} else {
			info = fallback
		}
	} else if err != nil {
		log.Debug(tag, "underlay refresh: %v", err)
		info = NetworkInfo{Type: NetworkDisconnected}
	}

	m.mu.Lock()

	// Last known DNS on same underlay
	if info.IfIndex != 0 &&
		info.IfIndex == prev.IfIndex &&
		len(info.DNSServers) == 0 &&
		len(prev.DNSServers) > 0 {
		info.DNSServers = append([]string(nil), prev.DNSServers...)
	}

	// Keep last good SSID if this refresh only got placeholders while still
	// on the same associated Wi-Fi underlay. BSSID is not populated on Windows.
	if info.IfIndex != 0 && info.IfIndex == prev.IfIndex && info.Type == NetworkWifi {
		if info.SSID == UnknownSSID && prev.SSID != "" && prev.SSID != UnknownSSID {
			info.SSID = prev.SSID
		}
	}

	if prev.Equal(info) {
		m.mu.Unlock()
		return
	}
	log.Debug(tag, "underlay changed: %s ifIndex=%d type=%d to %s ifIndex=%d type=%d ssid=%s",
		prev.InterfaceName, prev.IfIndex, prev.Type, info.InterfaceName, info.IfIndex, info.Type, info.SSID)

	m.current = info
	listeners := append([]func(NetworkInfo){}, m.listeners...)
	m.mu.Unlock()

	for _, fn := range listeners {
		fn(info)
	}
}

// underlayFromDefaultRoute enumerate adapters, keep only OperStatus-Up physical NICs, then pick the
// IPv4 default route with the lowest (route metric + interface Ipv4Metric).
// Down Wi-Fi NICs drop out here even if a stale 0.0.0.0/0 remains.
func underlayFromDefaultRoute(ctx context.Context) (NetworkInfo, error) {
	addrs, err := winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return NetworkInfo{}, err
	}

	viable := make(map[winipcfg.LUID]*winipcfg.IPAdapterAddresses, len(addrs))
	tunnelLUIDs := make(map[winipcfg.LUID]struct{})
	for _, a := range addrs {
		if isTunnelAdapter(a) {
			tunnelLUIDs[a.LUID] = struct{}{}
			continue
		}
		if !adapterViable(a) {
			continue
		}
		viable[a.LUID] = a
	}

	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("forward table: %w", err)
	}

	type candidate struct {
		adapter *winipcfg.IPAdapterAddresses
		metric  uint32
	}
	var cands []candidate
	sawTunDefault := false
	cache := &wifiCache{}

	for i := range rows {
		r := &rows[i]
		if r.Loopback || r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		if _, tun := tunnelLUIDs[r.InterfaceLUID]; tun {
			sawTunDefault = true
			continue
		}
		a := viable[r.InterfaceLUID]
		if a == nil {
			continue
		}
		cands = append(cands, candidate{
			adapter: a,
			metric:  r.Metric + a.Ipv4Metric,
		})
	}

	if len(cands) == 0 {
		if sawTunDefault {
			return NetworkInfo{}, errPhysicalDefaultHidden
		}
		return NetworkInfo{Type: NetworkDisconnected}, nil
	}

	best := cands[0]
	for _, c := range cands[1:] {
		if c.metric < best.metric {
			best = c
		}
	}

	// Prefer a still-associated underlay over a leftover Wi-Fi default route
	// whose adapter is Up but not joined (WLAN isState != connected).
	if best.adapter.IfType == winipcfg.IfTypeIEEE80211 {
		if !cache.associated(best.adapter) {
			var next *candidate
			nextMetric := ^uint32(0)
			for i := range cands {
				c := &cands[i]
				if c.adapter.IfType == winipcfg.IfTypeIEEE80211 && !cache.associated(c.adapter) {
					continue
				}
				if c.metric < nextMetric {
					nextMetric = c.metric
					next = c
				}
			}
			if next == nil {
				return NetworkInfo{Type: NetworkDisconnected}, nil
			}
			best = *next
		}
	}

	var wifi wifiDetails
	if best.adapter.IfType == winipcfg.IfTypeIEEE80211 {
		wifi = cache.lookup(best.adapter)
	}
	return networkInfoFromAdapter(ctx, best.adapter, wifi)
}

func adapterViable(a *winipcfg.IPAdapterAddresses) bool {
	if a.OperStatus != winipcfg.IfOperStatusUp {
		return false
	}
	if a.IfType == winipcfg.IfTypeSoftwareLoopback {
		return false
	}
	if a.Flags&winipcfg.IPAAFlagIpv4Enabled == 0 {
		return false
	}
	// Extra vs Tailscale: radio-off Wi-Fi can linger OperStatus-Up with
	// media disconnected. Skip those so leftover default routes cannot win.
	if ifrow, err := a.LUID.Interface(); err == nil &&
		ifrow.MediaConnectState == winipcfg.MediaConnectStateDisconnected {
		return false
	}
	return true
}

type wifiCache struct {
	byLUID map[winipcfg.LUID]wifiDetails
}

func (c *wifiCache) lookup(a *winipcfg.IPAdapterAddresses) wifiDetails {
	if c.byLUID == nil {
		c.byLUID = make(map[winipcfg.LUID]wifiDetails)
	}
	if d, ok := c.byLUID[a.LUID]; ok {
		return d
	}
	d := lookupWifi(a)
	c.byLUID[a.LUID] = d
	return d
}

func (c *wifiCache) associated(a *winipcfg.IPAdapterAddresses) bool {
	d := c.lookup(a)
	if d.Wireless {
		return d.Associated
	}
	// WLAN API did not recognize the adapter; do not drop a viable default.
	return true
}

func lookupWifi(a *winipcfg.IPAdapterAddresses) wifiDetails {
	var ifaceGUID windows.GUID
	desc := a.Description()
	if ifrow, err := a.LUID.Interface(); err == nil {
		ifaceGUID = ifrow.InterfaceGUID
		if desc == "" {
			desc = ifrow.Description()
		}
	}
	d, err := wifiInfoForInterface(a.LUID, ifaceGUID, desc)
	if err != nil {
		log.Debug(tag, "wifi info ifIndex=%d iface=%s guid=%s: %v",
			a.IfIndex, a.FriendlyName(), ifaceGUID.String(), err)
	}
	return d
}

func bestPhysicalUnderlay(ctx context.Context, prev NetworkInfo) (NetworkInfo, error) {
	addrs, err := winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return NetworkInfo{Type: NetworkDisconnected}, err
	}

	cache := &wifiCache{}
	try := func(a *winipcfg.IPAdapterAddresses) (NetworkInfo, bool) {
		if isTunnelAdapter(a) || !adapterViable(a) {
			return NetworkInfo{}, false
		}
		var wifi wifiDetails
		if a.IfType == winipcfg.IfTypeIEEE80211 {
			if !cache.associated(a) {
				return NetworkInfo{}, false
			}
			wifi = cache.lookup(a)
		}
		info, ierr := networkInfoFromAdapter(ctx, a, wifi)
		if ierr != nil || (!info.HasIPv4 && !info.HasIPv6) {
			return NetworkInfo{}, false
		}
		return info, true
	}

	if prev.IfIndex != 0 {
		for _, a := range addrs {
			if a.IfIndex == prev.IfIndex {
				if info, ok := try(a); ok {
					return info, nil
				}
				break
			}
		}
	}
	for _, a := range addrs {
		if info, ok := try(a); ok {
			return info, nil
		}
	}
	return NetworkInfo{Type: NetworkDisconnected}, nil
}

func networkInfoFromAdapter(ctx context.Context, a *winipcfg.IPAdapterAddresses, wifi wifiDetails) (NetworkInfo, error) {
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
		// This adapter already won default-route selection. Keep it as Wi-Fi
		// even if WLAN association flickered; do not report disconnected.
		if wifi.SSID != "" {
			info.SSID = wifi.SSID
		} else {
			info.SSID = UnknownSSID
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

func isTunnelAdapter(a *winipcfg.IPAdapterAddresses) bool {
	name := strings.ToLower(a.FriendlyName() + " " + a.AdapterName())
	prefix := strings.ToLower(constants.TunPrefix)
	return strings.Contains(name, prefix) ||
		strings.Contains(name, "wgtun") ||
		strings.Contains(name, "wintun") ||
		strings.Contains(name, "wireguard") ||
		a.IfType == winipcfg.IfTypeTunnel
}
