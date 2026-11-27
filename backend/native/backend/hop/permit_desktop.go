//go:build !android

package hop

import (
	"net"
	"net/netip"

	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall/osfirewall/firewallmgr"
)

// PermitUnderlayPeers adds the outer peer addresses to the independent kill
// switch pass table. Used on the local-proxy path, which has no OS router to
// install host routes.
func PermitUnderlayPeers(outerConfig string) {
	if outerConfig == "" {
		return
	}
	conf, err := wireproxyawg.ParseConfigString(outerConfig)
	if err != nil || conf.Device == nil {
		return
	}
	var peers []netip.Prefix
	for _, peer := range conf.Device.Peers {
		if peer.Endpoint == nil || *peer.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(*peer.Endpoint)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.IsValid() || !addr.IsGlobalUnicast() {
			continue
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		peers = append(peers, netip.PrefixFrom(addr, bits))
	}
	if len(peers) == 0 {
		return
	}
	fw, err := firewallmgr.Get()
	if err != nil {
		log.Debug(tag, "permit underlay peers: firewall: %v", err)
		return
	}
	if !fw.IsEnabled() {
		return
	}
	type routePermitter interface {
		UpdatePermittedRoutes([]netip.Prefix) error
	}
	p, ok := fw.(routePermitter)
	if !ok {
		return
	}
	if err := p.UpdatePermittedRoutes(peers); err != nil {
		log.Error(tag, "permit underlay peers: %v", err)
	}
}
