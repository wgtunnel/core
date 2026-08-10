//go:build linux

package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	resolvedDest      = "org.freedesktop.resolve1"
	resolvedManagerIF = "org.freedesktop.resolve1.Manager"
	resolvedLinkIF    = "org.freedesktop.resolve1.Link"
	resolvedPath      = "/org/freedesktop/resolve1"
)

// Domain is a systemd-resolved link domain entry.
type Domain struct {
	Name    string
	Routing bool // true for routing domains like "~."
}

// Resolved is a small client for org.freedesktop.resolve1.
type Resolved struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func OpenResolved() (*Resolved, error) {
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, fmt.Errorf("resolved: system bus: %w", err)
	}

	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("resolved: auth: %w", err)
	}
	if err := conn.Hello(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("resolved: hello: %w", err)
	}

	return &Resolved{
		conn: conn,
		obj:  conn.Object(resolvedDest, dbus.ObjectPath(resolvedPath)),
	}, nil
}

func (r *Resolved) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

func (r *Resolved) call(ctx context.Context, method string, args ...interface{}) *dbus.Call {
	return r.obj.CallWithContext(ctx, resolvedManagerIF+"."+method, 0, args...)
}

// Available reports whether resolved responds to a simple request.
func (r *Resolved) Available(ctx context.Context) bool {
	if r == nil {
		return false
	}
	var (
		addresses []struct {
			IfIndex int
			Family  int
			Address []byte
		}
		canonical string
		outflags  uint64
	)
	call := r.call(ctx, "ResolveHostname", 0, "localhost", unix.AF_UNSPEC, uint64(0))
	if call.Err != nil {
		return false
	}
	return call.Store(&addresses, &canonical, &outflags) == nil
}

func (r *Resolved) SetLinkDNS(ctx context.Context, ifIndex int, servers []netip.Addr) error {
	type dnsEntry struct {
		Family  int32
		Address []byte
	}
	entries := make([]dnsEntry, 0, len(servers))
	for _, ip := range servers {
		fam := int32(unix.AF_INET)
		if ip.Is6() {
			fam = int32(unix.AF_INET6)
		}
		entries = append(entries, dnsEntry{
			Family:  fam,
			Address: ip.AsSlice(),
		})
	}
	call := r.call(ctx, "SetLinkDNS", ifIndex, entries)
	if call.Err != nil {
		return fmt.Errorf("resolved: SetLinkDNS: %w", call.Err)
	}
	return nil
}

func (r *Resolved) SetLinkDomains(ctx context.Context, ifIndex int, domains []Domain) error {
	type domainEntry struct {
		Domain  string
		Routing bool
	}
	entries := make([]domainEntry, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, domainEntry{
			Domain:  d.Name,
			Routing: d.Routing,
		})
	}
	call := r.call(ctx, "SetLinkDomains", ifIndex, entries)
	if call.Err != nil {
		return fmt.Errorf("resolved: SetLinkDomains: %w", call.Err)
	}
	return nil
}

func (r *Resolved) SetLinkDefaultRoute(ctx context.Context, ifIndex int, enabled bool) error {
	call := r.call(ctx, "SetLinkDefaultRoute", ifIndex, enabled)
	if call.Err != nil {
		return fmt.Errorf("resolved: SetLinkDefaultRoute: %w", call.Err)
	}
	return nil
}

func (r *Resolved) RevertLink(ctx context.Context, ifIndex int) error {
	call := r.call(ctx, "RevertLink", ifIndex)
	if call.Err != nil {
		return fmt.Errorf("resolved: RevertLink: %w", call.Err)
	}
	return nil
}

// ApplyTunnelDNS configures the TUN link
func (r *Resolved) ApplyTunnelDNS(
	ctx context.Context,
	ifIndex int,
	servers []netip.Addr,
	searchDomains []string,
	fullTunnel bool,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.SetLinkDNS(ctx, ifIndex, servers); err != nil {
		return err
	}

	domains := make([]Domain, 0, len(searchDomains)+1)
	for _, d := range searchDomains {
		domains = append(domains, Domain{Name: d, Routing: false})
	}
	if fullTunnel && len(servers) > 0 {
		domains = append(domains, Domain{Name: "~.", Routing: true})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.SetLinkDomains(ctx, ifIndex, domains); err != nil {
		return err
	}

	if fullTunnel {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.SetLinkDefaultRoute(ctx, ifIndex, true); err != nil {
			return err
		}
	}
	return nil
}

// RevertTunnelDNS clears TUN link DNS settings.
func (r *Resolved) RevertTunnelDNS(ctx context.Context, ifIndex int) error {
	// Best-effort clear of default route before full revert
	_ = r.SetLinkDefaultRoute(ctx, ifIndex, false)
	return r.RevertLink(ctx, ifIndex)
}

// LinkDNS returns DNS server addresses configured on a link.
func (r *Resolved) LinkDNS(ctx context.Context, ifIndex int) ([]netip.Addr, error) {
	var linkPath dbus.ObjectPath
	if err := r.call(ctx, "GetLink", int32(ifIndex)).Store(&linkPath); err != nil {
		return nil, fmt.Errorf("resolved: GetLink(%d): %w", ifIndex, err)
	}

	link := r.conn.Object(resolvedDest, linkPath)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	variant, err := link.GetProperty(resolvedLinkIF + ".DNS")
	if err != nil {
		return nil, fmt.Errorf("resolved: DNS property: %w", err)
	}

	entries, err := parseResolvedDNSProperty(variant.Value())
	if err != nil {
		return nil, err
	}

	out := make([]netip.Addr, 0, len(entries))
	seen := map[netip.Addr]struct{}{}
	for _, e := range entries {
		ip := net.IP(e.Address)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out, nil
}

func (r *Resolved) LinkDNSHostPorts(ctx context.Context, ifIndex int) ([]string, error) {
	addrs, err := r.LinkDNS(ctx, ifIndex)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.String(), "53"))
	}
	return out, nil
}

type dnsPropEntry struct {
	Family  int32
	Address []byte
}

func parseResolvedDNSProperty(v interface{}) ([]dnsPropEntry, error) {
	var entries []dnsPropEntry
	if err := dbus.Store([]interface{}{v}, &entries); err == nil {
		return entries, nil
	}

	// Fallback
	switch val := v.(type) {
	case [][]interface{}:
		for _, item := range val {
			if len(item) != 2 {
				continue
			}
			fam, _ := item[0].(int32)
			addr, _ := item[1].([]byte)
			entries = append(entries, dnsPropEntry{Family: fam, Address: addr})
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("resolved: unsupported DNS property type %T", v)
	}
}
