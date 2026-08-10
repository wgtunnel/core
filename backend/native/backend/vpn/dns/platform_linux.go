//go:build linux

package dns

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/wgtunnel/backend/log"

	"github.com/wgtunnel/backend/vpn/dns/linux"
)

const tag = "SetDNS"

// SetDNS applies tunnel DNS for the TUN interface.
// Order: systemd-resolved first, resolv.conf fallback
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
	if len(servers) == 0 && len(searchDomains) == 0 {
		log.Debug(tag, "Skipping DNS apply (empty)")
		return nil
	}

	// systemd-resolved first for per-link on TUN
	if r, err := linux.OpenResolved(); err == nil {
		defer r.Close()
		if r.Available(ctx) {
			idx, lerr := ifaceIndex(iface)
			if lerr != nil {
				log.Error(tag, "resolved: get iface index for %s: %v", iface, lerr)
			} else {
				log.Debug(tag, "Configuring DNS via systemd-resolved on %s (ifIndex=%d)...", iface, idx)
				if err := r.ApplyTunnelDNS(ctx, idx, servers, searchDomains, fullTunnel); err != nil {
					log.Error(tag, "resolved apply failed: %v", err)
				} else {
					return nil
				}
			}
		} else {
			log.Debug(tag, "systemd-resolved not available")
		}
	} else {
		log.Debug(tag, "systemd-resolved open failed: %v", err)
	}

	// resolv.conf fallback
	log.Debug(tag, "Falling back to resolv.conf...")
	if err := ctx.Err(); err != nil {
		return err
	}
	return linux.WriteResolvConf(servers, searchDomains)
}

// RevertDNS undoes a previous SetDNS for the TUN interface.
// Order: systemd-resolved first, resolv.conf fallback
func RevertDNS(ctx context.Context, iface string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// systemd-resolved
	if r, err := linux.OpenResolved(); err == nil {
		defer r.Close()
		if r.Available(ctx) {
			idx, lerr := ifaceIndex(iface)
			if lerr != nil {
				log.Error(tag, "resolved: get iface index for %s: %v", iface, lerr)
			} else {
				log.Debug(tag, "Reverting DNS via systemd-resolved on %s (ifIndex=%d)...", iface, idx)
				if err := r.RevertTunnelDNS(ctx, idx); err != nil {
					log.Error(tag, "resolved revert failed: %v", err)
				} else {
					return nil
				}
			}
		} else {
			log.Debug(tag, "systemd-resolved not available")
		}
	} else {
		log.Debug(tag, "systemd-resolved open failed: %v", err)
	}

	// resolv.conf fallback
	log.Debug(tag, "Reverting DNS via resolv.conf backup...")
	if err := ctx.Err(); err != nil {
		return err
	}
	return linux.RestoreResolvConf()
}

// ReadUnderlayDNS returns underlay nameservers as host:port for the physical interface.
// Order: systemd-resolved, NetworkManager fallback
// Returns (nil, nil) when none found.
func ReadUnderlayDNS(ctx context.Context, ifIndex uint32, ifName string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ifIndex != 0 {
		if r, err := linux.OpenResolved(); err == nil {
			defer r.Close()
			servers, err := r.LinkDNSHostPorts(ctx, int(ifIndex))
			if err == nil && len(servers) > 0 {
				return servers, nil
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if ifName != "" {
		if nm, err := linux.OpenNetworkManager(); err == nil {
			defer nm.Close()
			servers, err := nm.DeviceDNSHostPorts(ctx, ifName)
			if err == nil && len(servers) > 0 {
				return servers, nil
			}
		}
	}

	return nil, nil
}

func ifaceIndex(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("link %s: %w", name, err)
	}
	return link.Attrs().Index, nil
}
