//go:build darwin

package network

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

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

type darwinMonitor struct {
	started   bool
	mu        sync.RWMutex
	current   NetworkInfo
	listeners []func(NetworkInfo)

	stopOnce sync.Once
	stopCh   chan struct{}
	routeFd  int

	ctx    context.Context
	cancel context.CancelFunc
}

func NewMonitor() Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &darwinMonitor{
		stopCh: make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (m *darwinMonitor) Current() NetworkInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *darwinMonitor) Notify(fn func(NetworkInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, fn)
}

func (m *darwinMonitor) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	m.refresh()

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Error(tag, "AF_ROUTE socket: %v (polling only)", err)
		go m.pollLoop()
		return nil
	}
	m.routeFd = fd

	go func() {
		defer unix.Close(fd)
		deb := util.NewDebouncer(debounceInterval)
		buf := make([]byte, 2048)
		readCh := make(chan struct{}, 1)
		go func() {
			for {
				_, err := unix.Read(fd, buf)
				if err != nil {
					return
				}
				select {
				case readCh <- struct{}{}:
				default:
				}
			}
		}()
		for {
			select {
			case <-m.stopCh:
				deb.Stop()
				return
			case <-readCh:
				deb.Hit()
			case <-deb.C:
				deb.Fired()
				m.refresh()
			}
		}
	}()
	return nil
}

func (m *darwinMonitor) pollLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			m.refresh()
		}
	}
}

func (m *darwinMonitor) Stop() {
	m.stopOnce.Do(func() {
		m.cancel()
		close(m.stopCh)
		if m.routeFd != 0 {
			_ = unix.Close(m.routeFd)
			m.routeFd = 0
		}
	})
}

func (m *darwinMonitor) refresh() {
	m.mu.RLock()
	prev := m.current
	m.mu.RUnlock()
	info := lookupUnderlay(m.ctx, prev)
	m.mu.Lock()
	changed := !m.current.Equal(info)
	if changed {
		m.current = info
	}
	listeners := append([]func(NetworkInfo){}, m.listeners...)
	m.mu.Unlock()
	if !changed {
		return
	}
	log.Debug(tag, "underlay if=%s idx=%d type=%d dns=%d", info.InterfaceName, info.IfIndex, info.Type, len(info.DNSServers))
	for _, fn := range listeners {
		fn(info)
	}
}

func lookupUnderlay(ctx context.Context, prev NetworkInfo) NetworkInfo {
	d := LookupPhysicalDefault4()
	if d.IfName == "" {
		d = LookupPhysicalDefault6()
	}
	if d.IfName == "" {
		return NetworkInfo{Type: NetworkDisconnected}
	}
	ifName := d.IfName
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return NetworkInfo{Type: NetworkDisconnected, InterfaceName: ifName, IfIndex: d.IfIndex}
	}
	info := NetworkInfo{
		Type:          classifyIface(ifName),
		InterfaceName: ifName,
		IfIndex:       uint32(iface.Index),
		SSID:          UnknownSSID,
		BSSID:         UnknownBSSID,
	}
	if info.Type == NetworkWifi {
		// Only derive SSID on a genuine network change
		// otherwise reuse the cached value instead
		if prev.Type == NetworkWifi && prev.InterfaceName == ifName && prev.HasKnownSSID() {
			info.SSID = prev.SSID
		} else if ssid := currentWifiSSID(d.Gateway); ssid != "" {
			info.SSID = ssid
		}
	}
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		if ipnet.IP.To4() != nil {
			info.HasIPv4 = true
		} else if ipnet.IP.IsGlobalUnicast() {
			info.HasIPv6 = true
		}
	}
	if servers, err := dns.ReadUnderlayDNS(ctx, info.IfIndex, ifName); err == nil {
		info.DNSServers = servers
	}
	return info
}

func isTunnelIface(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, constants.TunPrefix) ||
		strings.HasPrefix(n, "utun") ||
		strings.HasPrefix(n, "tun") ||
		strings.HasPrefix(n, "wg")
}

func classifyIface(name string) NetworkType {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "en"):
		return NetworkWifi
	case strings.Contains(n, "eth") || strings.HasPrefix(n, "bridge"):
		return NetworkEthernet
	default:
		return NetworkOther
	}
}
