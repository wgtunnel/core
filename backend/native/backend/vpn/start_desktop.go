//go:build !android

package vpn

import "C"
import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall/firewallmgr"
	"github.com/wgtunnel/backend/vpn/router"
	"github.com/wgtunnel/backend/vpn/router/osrouter"
)

type pendingInterface struct {
	iface  string
	tun    tun.Device
	router router.Router
}

type desktopTunnelExtras struct {
	router router.Router
}

var (
	pendingMu      sync.Mutex
	pendingByIface = map[string]*pendingInterface{}

	desktopMu     sync.Mutex
	desktopExtras = map[int32]*desktopTunnelExtras{}
)

// awgCreateInterface creates the tunnel interface
// config: quick config used only to build router.Config
// Endpoints may still be hostnames and peer endpoint routes can be filled later after resolve.
//
//export createInterface
func createInterface(ifName string, config string) int32 {
	// JNI go_string points at GetStringUTFChars. ReleaseStringUTFChars runs
	// when the JNI wrapper returns, so anything stored (map keys, iface names)
	// must be copied
	ifName = strings.Clone(ifName)
	config = strings.Clone(config)

	conf, err := wireproxyawg.ParseConfigString(config)
	if err != nil {
		log.Error(tag, "CreateInterface parse: %v", err)
		return -1
	}

	// Reserve the iface name so a second caller fails immediately
	pendingMu.Lock()
	if _, exists := pendingByIface[ifName]; exists {
		pendingMu.Unlock()
		log.Error(tag, "interface %s already pending", ifName)
		return -1
	}
	pendingByIface[ifName] = &pendingInterface{iface: ifName} // placeholder
	pendingMu.Unlock()

	cleanupReserve := func() {
		pendingMu.Lock()
		// Only delete if still the empty placeholder
		if p := pendingByIface[ifName]; p != nil && p.tun == nil && p.router == nil {
			delete(pendingByIface, ifName)
		}
		pendingMu.Unlock()
	}

	mtu := conf.Device.MTU
	if mtu == 0 {
		mtu = 1280
	}

	tunDev, err := tun.CreateTUN(ifName, mtu)
	if err != nil {
		log.Error(tag, "CreateTUN: %v", err)
		removeStaleTun(ifName)
		tunDev, err = tun.CreateTUN(ifName, mtu)
		if err != nil {
			cleanupReserve()
			log.Error(tag, "CreateTUN retry: %v", err)
			return -1
		}
		log.Debug(tag, "CreateTUN succeeded after removing stale %s", ifName)
	}

	fw, err := firewallmgr.Get()
	if err != nil {
		_ = tunDev.Close()
		cleanupReserve()
		log.Error(tag, "firewall: %v", err)
		return -1
	}

	rt, err := osrouter.New(ifName, fw, tunDev)
	if err != nil {
		_ = tunDev.Close()
		cleanupReserve()
		log.Error(tag, "router: %v", err)
		return -1
	}

	cfg, err := parseToRouterConfig(conf, 0)
	if err != nil {
		_ = rt.Close()
		_ = tunDev.Close()
		cleanupReserve()
		log.Error(tag, "router config: %v", err)
		return -1
	}

	if err := rt.Set(cfg); err != nil {
		_ = rt.Close()
		_ = tunDev.Close()
		cleanupReserve()
		log.Error(tag, "router.Set: %v", err)
		return -1
	}

	// Commit real resources
	pendingMu.Lock()
	pendingByIface[ifName] = &pendingInterface{
		iface:  ifName,
		tun:    tunDev,
		router: rt,
	}
	pendingMu.Unlock()

	log.Debug(tag, "VPN interface %s created (black-hole until TurnOn)", ifName)
	return 0
}

//export destroyInterface
func destroyInterface(ifName string) {
	ifName = strings.Clone(ifName)

	pendingMu.Lock()
	p := pendingByIface[ifName]
	delete(pendingByIface, ifName)
	pendingMu.Unlock()
	if p != nil {
		if p.router != nil {
			_ = p.router.Close()
		}
		if p.tun != nil {
			_ = p.tun.Close()
		}
	} else {
		// Pending missed. JNI key was not cloned, takePending already consumed
		// it, or a previous process crashed. Still drop leftover ip/nftables.
		cleanupOrphanedDesktopIface(ifName)
	}
	// Always drop a leftover kernel iface, even if we no longer hold pending
	// state
	removeStaleTun(ifName)
	log.Debug(tag, "VPN interface %s destroyed", ifName)
}

// takePending transfers TUN ownership to caller
func takePending(ifName string) (tun.Device, router.Router, error) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	p := pendingByIface[ifName]
	if p == nil || p.tun == nil {
		keys := make([]string, 0, len(pendingByIface))
		for k, v := range pendingByIface {
			tunReady := v != nil && v.tun != nil
			keys = append(keys, fmt.Sprintf("%q(tun=%v)", k, tunReady))
		}
		return nil, nil, fmt.Errorf("no pending interface %q (have %v)", ifName, keys)
	}
	delete(pendingByIface, ifName)
	t, r := p.tun, p.router
	p.tun = nil // prevent double close
	return t, r, nil
}

//export startVpn
func startVpn(
	handle int32,
	ifName string,
	_tunFd int32,
	config string,
	dnsConfig string,
	uapiPath string,
) int32 {

	ifName = strings.Clone(ifName)
	config = strings.Clone(config)
	dnsConfig = strings.Clone(dnsConfig)
	uapiPath = strings.Clone(uapiPath)

	tunDev, rt, err := takePending(ifName)
	if err != nil {
		log.Error(tag, "TurnOn: %v", err)
		return -1
	}

	rc := startVpnDevice(handle, ifName, tunDev, config, dnsConfig, uapiPath)
	if rc < 0 {
		if rt != nil {
			_ = rt.Close()
		}
		if tunDev != nil {
			_ = tunDev.Close()
		}
		removeStaleTun(ifName)
		return -1
	}

	if conf, err := wireproxyawg.ParseConfigString(config); err == nil {
		if cfg, err := parseToRouterConfig(conf, 0); err == nil && rt != nil {
			_ = rt.Set(cfg)
		}
	}

	desktopMu.Lock()
	desktopExtras[handle] = &desktopTunnelExtras{router: rt}
	desktopMu.Unlock()
	return 0
}

// called from shared awgTurnOff after device close
func closeDesktopExtras(id int32) {
	desktopMu.Lock()
	ex := desktopExtras[id]
	delete(desktopExtras, id)
	desktopMu.Unlock()
	if ex != nil && ex.router != nil {
		_ = ex.router.Close()
	}
}

func parseToRouterConfig(conf *wireproxyawg.Configuration, listenPort uint16) (*router.Config, error) {
	device := conf.Device
	if device == nil {
		return nil, errors.New("no [Interface] section found in config")
	}
	cfg := &router.Config{
		MTU: device.MTU,
	}
	for _, addr := range device.Address {
		bitLen := 32
		if addr.Is6() {
			bitLen = 128
		}
		cfg.TunnelAddrs = append(cfg.TunnelAddrs, netip.PrefixFrom(addr, bitLen).Masked())
	}
	cfg.DNS = device.DNS
	cfg.SearchDomains = device.SearchDomains
	cfg.ListenPort = listenPort

	for _, peer := range device.Peers {
		cfg.Routes = append(cfg.Routes, peer.AllowedIPs...)

		if peer.Endpoint == nil || *peer.Endpoint == "" {
			continue
		}

		host, _, err := net.SplitHostPort(*peer.Endpoint)
		if err != nil {
			log.Debug(tag, "Skipping peer endpoint %q: %v", *peer.Endpoint, err)
			continue
		}
		// Hostname, we resolve later
		if _, err := netip.ParseAddr(host); err != nil {
			continue
		}

		epPrefix, _, err := wireproxyawg.ParsePeerEndpoint(*peer.Endpoint)
		if err != nil {
			log.Debug(tag, "Skipping peer endpoint %q: %v", *peer.Endpoint, err)
			continue
		}
		if epPrefix.IsValid() && epPrefix.Addr().IsGlobalUnicast() && !epPrefix.Addr().IsPrivate() {
			cfg.PeerEndpoints = append(cfg.PeerEndpoints, epPrefix)
		}
	}
	return cfg, nil
}

func OnTunnelStopped(id int32) { closeDesktopExtras(id) }
