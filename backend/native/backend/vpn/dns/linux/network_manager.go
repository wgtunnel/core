//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/godbus/dbus/v5"
)

const (
	nmDest        = "org.freedesktop.NetworkManager"
	nmPath        = "/org/freedesktop/NetworkManager"
	nmIF          = "org.freedesktop.NetworkManager"
	nmDeviceIF    = "org.freedesktop.NetworkManager.Device"
	nmIP4ConfigIF = "org.freedesktop.NetworkManager.IP4Config"
	nmIP6ConfigIF = "org.freedesktop.NetworkManager.IP6Config"
)

// NetworkManager is a small client for underlay DNS reads
type NetworkManager struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func OpenNetworkManager() (*NetworkManager, error) {
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, fmt.Errorf("nm: system bus: %w", err)
	}
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("nm: auth: %w", err)
	}
	if err := conn.Hello(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("nm: hello: %w", err)
	}
	return &NetworkManager{
		conn: conn,
		obj:  conn.Object(nmDest, nmPath),
	}, nil
}

func (n *NetworkManager) Close() error {
	if n == nil || n.conn == nil {
		return nil
	}
	return n.conn.Close()
}

// Available reports whether NetworkManager is on the system bus.
func (n *NetworkManager) Available(ctx context.Context) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	if n == nil {
		return false
	}
	// Version property is a cheap presence check
	_, err := n.obj.GetProperty(nmIF + ".Version")
	return err == nil
}

// DeviceDNS returns IPv4+IPv6 nameservers for a device by interface name.
func (n *NetworkManager) DeviceDNS(ctx context.Context, ifName string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ifName == "" {
		return nil, fmt.Errorf("nm: empty interface name")
	}

	var devicePath dbus.ObjectPath
	if err := n.obj.CallWithContext(ctx, nmIF+".GetDeviceByIpIface", 0, ifName).Store(&devicePath); err != nil {
		return nil, fmt.Errorf("nm: GetDeviceByIpIface(%s): %w", ifName, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	dev := n.conn.Object(nmDest, devicePath)

	var out []netip.Addr
	seen := map[netip.Addr]struct{}{}

	add := func(addr netip.Addr) {
		if !addr.IsValid() || addr.IsUnspecified() {
			return
		}
		addr = addr.Unmap()
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	// IPv4
	if addrs, err := n.nameserversFromIPConfig(dev, nmDeviceIF+".Ip4Config", true); err == nil {
		for _, a := range addrs {
			add(a)
		}
	}
	// IPv6
	if addrs, err := n.nameserversFromIPConfig(dev, nmDeviceIF+".Ip6Config", false); err == nil {
		for _, a := range addrs {
			add(a)
		}
	}

	return out, nil
}

// DeviceDNSHostPorts is convenience for the monitor.
func (n *NetworkManager) DeviceDNSHostPorts(ctx context.Context, ifName string) ([]string, error) {
	addrs, err := n.DeviceDNS(ctx, ifName)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.String(), "53"))
	}
	return out, nil
}

func (n *NetworkManager) nameserversFromIPConfig(
	dev dbus.BusObject,
	configProp string,
	ipv4 bool,
) ([]netip.Addr, error) {
	variant, err := dev.GetProperty(configProp)
	if err != nil {
		return nil, err
	}
	cfgPath, ok := variant.Value().(dbus.ObjectPath)
	if !ok || cfgPath == "" || cfgPath == "/" {
		return nil, fmt.Errorf("nm: no ip config")
	}

	cfg := n.conn.Object(nmDest, cfgPath)
	ififace := nmIP4ConfigIF
	if !ipv4 {
		ififace = nmIP6ConfigIF
	}

	// Prefer NameserverData when present (NM newer)
	if ns, err := n.parseNameserverData(cfg, ififace+".NameserverData"); err == nil && len(ns) > 0 {
		return ns, nil
	}

	// Fallback: Nameservers
	if ipv4 {
		return n.parseIP4Nameservers(cfg, ififace+".Nameservers")
	}
	return n.parseIP6Nameservers(cfg, ififace+".Nameservers")
}

func (n *NetworkManager) parseNameserverData(cfg dbus.BusObject, prop string) ([]netip.Addr, error) {
	variant, err := cfg.GetProperty(prop)
	if err != nil {
		return nil, err
	}
	raw, ok := variant.Value().([]map[string]dbus.Variant)
	if !ok {
		return nil, fmt.Errorf("nm: unexpected NameserverData type %T", variant.Value())
	}
	var out []netip.Addr
	for _, m := range raw {
		v, ok := m["address"]
		if !ok {
			continue
		}
		s, ok := v.Value().(string)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		out = append(out, addr)
	}
	return out, nil
}

func (n *NetworkManager) parseIP4Nameservers(cfg dbus.BusObject, prop string) ([]netip.Addr, error) {
	variant, err := cfg.GetProperty(prop)
	if err != nil {
		return nil, err
	}
	// array of uint32, network byte order
	vals, ok := variant.Value().([]uint32)
	if !ok {
		return nil, fmt.Errorf("nm: unexpected IPv4 Nameservers type %T", variant.Value())
	}
	var out []netip.Addr
	for _, v := range vals {
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], v)
		ip := net.IPv4(b[0], b[1], b[2], b[3])
		if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
			out = append(out, addr)
		}
	}
	return out, nil
}

func (n *NetworkManager) parseIP6Nameservers(cfg dbus.BusObject, prop string) ([]netip.Addr, error) {
	variant, err := cfg.GetProperty(prop)
	if err != nil {
		return nil, err
	}
	vals, ok := variant.Value().([][]byte)
	if !ok {
		return nil, fmt.Errorf("nm: unexpected IPv6 Nameservers type %T", variant.Value())
	}
	var out []netip.Addr
	for _, b := range vals {
		if addr, ok := netip.AddrFromSlice(b); ok {
			out = append(out, addr)
		}
	}
	return out, nil
}
