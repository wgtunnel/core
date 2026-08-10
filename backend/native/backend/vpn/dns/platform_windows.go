//go:build windows

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/wgtunnel/backend/log"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tag = "SetDNS"

// SetDNS applies tunnel DNS on the TUN interface by interface name.
func SetDNS(
	ctx context.Context,
	iface string,
	servers []netip.Addr,
	searchDomains []string,
	fullTunnel bool,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = fullTunnel

	if len(servers) == 0 && len(searchDomains) == 0 {
		log.Debug(tag, "Skipping DNS apply (empty)")
		return nil
	}

	luid, err := luidFromIface(iface)
	if err != nil {
		return err
	}

	var v4, v6 []netip.Addr
	for _, d := range servers {
		switch {
		case d.Is4():
			v4 = append(v4, d)
		case d.Is6() && nettest.SupportsIPv6():
			v6 = append(v6, d)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if len(v4) > 0 || len(searchDomains) > 0 {
		if err := luid.SetDNS(windows.AF_INET, v4, searchDomains); err != nil {
			return fmt.Errorf("set v4 dns: %w", err)
		}
	}
	if len(v6) > 0 || len(searchDomains) > 0 {
		if err := luid.SetDNS(windows.AF_INET6, v6, searchDomains); err != nil {
			return fmt.Errorf("set v6 dns: %w", err)
		}
	}
	log.Debug(tag, "Configured DNS on %s (v4=%d v6=%d search=%d)",
		iface, len(v4), len(v6), len(searchDomains))
	return nil
}

// RevertDNS clears DNS on the TUN interface.
func RevertDNS(ctx context.Context, iface string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	luid, err := luidFromIface(iface)
	if err != nil {
		return err
	}

	_ = luid.FlushDNS(windows.AF_INET)
	_ = luid.FlushDNS(windows.AF_INET6)
	log.Debug(tag, "Flushed DNS on %s", iface)
	return nil
}

// ReadUnderlayDNS returns underlay nameservers as host:port for the physical interface.
func ReadUnderlayDNS(ctx context.Context, ifIndex uint32, ifName string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	addrs, err := winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagDefault,
	)
	if err != nil {
		return nil, fmt.Errorf("dns: GetAdaptersAddresses: %w", err)
	}

	for _, a := range addrs {
		if !adapterMatches(a, ifIndex, ifName) {
			continue
		}
		if isTunnelAdapter(a) {
			continue
		}
		return dnsServersFromAdapter(a), nil
	}

	// Retry with all interfaces if not found
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addrs, err = winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if !adapterMatches(a, ifIndex, ifName) || isTunnelAdapter(a) {
			continue
		}
		return dnsServersFromAdapter(a), nil
	}

	return nil, nil
}

func luidFromIface(name string) (winipcfg.LUID, error) {
	if name == "" {
		return 0, fmt.Errorf("dns: empty iface name")
	}
	addrs, err := winipcfg.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		winipcfg.GAAFlagIncludeAllInterfaces,
	)
	if err != nil {
		return 0, err
	}
	for _, a := range addrs {
		if a.FriendlyName() == name || a.AdapterName() == name {
			return a.LUID, nil
		}
	}
	return 0, fmt.Errorf("dns: interface %q not found", name)
}

func adapterMatches(a *winipcfg.IPAdapterAddresses, ifIndex uint32, ifName string) bool {
	if ifIndex != 0 && a.IfIndex == ifIndex {
		return true
	}
	if ifName != "" && (a.FriendlyName() == ifName || a.AdapterName() == ifName) {
		return true
	}
	return false
}

func isTunnelAdapter(a *winipcfg.IPAdapterAddresses) bool {
	name := strings.ToLower(a.FriendlyName() + " " + a.AdapterName())
	return strings.Contains(name, "wgtun") ||
		strings.Contains(name, "wintun") ||
		strings.Contains(name, "wireguard") ||
		a.IfType == winipcfg.IfTypeTunnel
}

func dnsServersFromAdapter(a *winipcfg.IPAdapterAddresses) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}

	for ns := a.FirstDNSServerAddress; ns != nil; ns = ns.Next {
		ip := ns.Address.IP()
		if len(ip) == 0 || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		hostPort := net.JoinHostPort(ip.String(), "53")
		if _, ok := seen[hostPort]; ok {
			continue
		}
		seen[hostPort] = struct{}{}
		out = append(out, hostPort)
	}
	return out
}
