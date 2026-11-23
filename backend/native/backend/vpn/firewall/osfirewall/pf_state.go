// Copyright (c) 2026 Zane Schepke / WG Tunnel

package osfirewall

import (
	"net/netip"
	"slices"
)

const (
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	// Kept even when LAN bypass is off. Deleting these
	// states breaks configd and mDNSResponder and can take the tunnel down according to Mullvad.
	mdnsPort       = 5353
	dhcpServerPort = 67
	dhcpClientPort = 68
)

// pfState is one pf state, reduced to the fields the kill decision uses.
// Ports are only meaningful for TCP and UDP.
type pfState struct {
	ifName     string
	proto      uint8
	local      netip.Addr
	localPort  uint16
	remote     netip.Addr
	remotePort uint16
}

// pfKeep is what the kill switch anchor passes, in the terms a state carries.
type pfKeep struct {
	tun        string
	listenPort uint16
	// pass is the pass table: LAN bypass and peer endpoints, matched on the remote side.
	pass []netip.Prefix
	// tunNets are the tun subnets, matched on either side.
	tunNets []netip.Prefix
	// vmIfaces pass if-bound, so their states carry the NIC name. A guest's
	// NAT state on the physical NIC is not kept.
	vmIfaces []string
}

// keepPFState reports whether an existing state may survive the kill switch.
// pf files states from rules without if-bound under the ALL group, not the
// interface, so the decision is made on addresses and ports. The interface
// name only helps for an if-bound state.
func keepPFState(st pfState, k pfKeep) bool {
	if st.ifName == "lo0" || (k.tun != "" && st.ifName == k.tun) || slices.Contains(k.vmIfaces, st.ifName) {
		return true
	}
	if !st.local.IsValid() || !st.remote.IsValid() {
		// Without both addresses the kill could not be keyed to this flow.
		return true
	}
	if st.local.IsLoopback() || st.remote.IsLoopback() {
		return true
	}
	if st.proto == protoTCP || st.proto == protoUDP {
		if st.localPort == mdnsPort || st.remotePort == mdnsPort {
			return true
		}
	}
	if st.proto == protoUDP {
		if k.listenPort != 0 && st.localPort == k.listenPort {
			return true
		}
		if (st.localPort == dhcpClientPort && st.remotePort == dhcpServerPort) ||
			(st.localPort == dhcpServerPort && st.remotePort == dhcpClientPort) {
			return true
		}
	}
	if st.proto == protoICMPv6 && (st.remote.IsLinkLocalUnicast() || st.remote.IsMulticast()) {
		// NDP
		return true
	}
	for _, p := range k.tunNets {
		if p.Contains(st.local) || p.Contains(st.remote) {
			return true
		}
	}
	for _, p := range k.pass {
		if p.Contains(st.remote) {
			return true
		}
	}
	return false
}
