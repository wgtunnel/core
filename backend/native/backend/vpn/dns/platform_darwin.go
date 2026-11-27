//go:build darwin

package dns

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/wgtunnel/backend/instance"
	"github.com/wgtunnel/backend/log"
	"golang.org/x/net/nettest"
)

const (
	tag = "SetDNS"
	// Release keeps the service IDs it always had, so it still removes what older
	// versions left. Other installs get their own, see serviceKey.
	releaseDNSServiceID    = "FF457792-79C0-4A25-8392-D875BBEACCA6"
	releaseTunnelServiceID = "FF457792-79C0-4A25-8392-D875BBEACCA7"
	// Older versions wrote split DNS files here, still cleaned up on apply and revert
	resolverDir    = "/etc/resolver"
	resolverPrefix = "wgtunnel."
)

// globalDNSKey holds the tunnel DNS servers.
func globalDNSKey() string { return serviceKey(releaseDNSServiceID, "dns") + "/DNS" }

// tunnelServiceKey is the service a full tunnel publishes as primary. macOS only sends
// A/AAAA queries for a family when some network service has a default route for it,
// so it registers the way a Network Extension VPN does.
func tunnelServiceKey() string { return serviceKey(releaseTunnelServiceID, "tunnel") }

// serviceKey gives each install its own service, so a beta and a release install never
// remove or overwrite each other's live entries.
func serviceKey(releaseID, role string) string {
	if instance.IsDefault() {
		return "State:/Network/Service/" + releaseID
	}
	h := sha256.Sum256([]byte("wgtunnel/" + instance.Name() + "/" + role))
	h[6] = h[6]&0x0f | 0x50
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("State:/Network/Service/%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// Profile DNS applies to all queries whenever servers are set, matching
// Linux, Windows, and the WireGuard apps, regardless of AllowedIPs.
func SetDNS(
	ctx context.Context,
	iface string,
	servers []netip.Addr,
	searchDomains []string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = iface
	_ = removeResolverFiles()
	usable := usableServers(servers)
	if len(usable) == 0 {
		_ = removeGlobalDNS()
		log.Debug(tag, "Skipping DNS apply (no usable servers, search=%d)", len(searchDomains))
		return nil
	}
	if err := setGlobalDNS(usable, searchDomains); err != nil {
		return err
	}
	log.Debug(tag, "Configured global DNS via scutil (servers=%d search=%d)", len(usable), len(searchDomains))
	return nil
}

func usableServers(servers []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(servers))
	for _, ip := range servers {
		if ip.Is6() && !nettest.SupportsIPv6() {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func RevertDNS(ctx context.Context, iface string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = iface
	err1 := removeGlobalDNS()
	err2 := removeResolverFiles()
	if err1 != nil {
		return err1
	}
	return err2
}

func ReadUnderlayDNS(ctx context.Context, ifIndex uint32, ifName string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ifName != "" {
		if servers := dnsFromIPConfig(ifName); len(servers) > 0 {
			return servers, nil
		}
	}
	_ = ifIndex
	return dnsFromScutil(ifName), nil
}

func setGlobalDNS(servers []netip.Addr, search []string) error {
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString("d.add SearchOrder # 100000\n")
	script.WriteString("d.add ServerAddresses *")
	for _, ip := range servers {
		script.WriteByte(' ')
		script.WriteString(ip.String())
	}
	script.WriteByte('\n')
	script.WriteString("d.add SupplementalMatchDomains * \"\"\n")
	if len(search) > 0 {
		script.WriteString("d.add SearchDomains *")
		for _, d := range search {
			script.WriteByte(' ')
			writeScutilString(&script, strings.TrimSuffix(d, "."))
		}
		script.WriteByte('\n')
	}
	script.WriteString("set ")
	script.WriteString(globalDNSKey())
	script.WriteString("\nquit\n")
	out, err := runScutil(script.String())
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out != "" {
		return fmt.Errorf("scutil set: %s", out)
	}
	return nil
}

func removeGlobalDNS() error {
	out, err := runScutil("remove " + globalDNSKey() + "\nquit\n")
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "No such key" {
		return nil
	}
	return fmt.Errorf("scutil remove: %s", out)
}

// SetTunnelService publishes iface as the primary service for each valid address.
// An invalid address removes that family.
func SetTunnelService(iface string, v4, v6 netip.Addr) error {
	if !v4.IsValid() && !v6.IsValid() {
		return RemoveTunnelService()
	}
	key := tunnelServiceKey()
	var script strings.Builder
	writeEntity := func(entity string, addr netip.Addr, lenKey, lenValue string) {
		if !addr.IsValid() {
			script.WriteString("remove " + key + "/" + entity + "\n")
			return
		}
		script.WriteString("d.init\n")
		script.WriteString("d.add Addresses * " + addr.String() + "\n")
		script.WriteString("d.add " + lenKey + " * " + lenValue + "\n")
		script.WriteString("d.add Router " + addr.String() + "\n")
		script.WriteString("d.add InterfaceName ")
		writeScutilString(&script, iface)
		script.WriteString("\nd.add OverridePrimary # 1\n")
		script.WriteString("set " + key + "/" + entity + "\n")
	}
	writeEntity("IPv4", v4, "SubnetMasks", "255.255.255.255")
	writeEntity("IPv6", v6, "PrefixLength #", "128")
	script.WriteString("quit\n")
	out, err := runScutil(script.String())
	if err != nil {
		return err
	}
	if out = onlyScutilErrors(out); out != "" {
		return fmt.Errorf("scutil set tunnel service: %s", out)
	}
	log.Debug(tag, "Published tunnel service (v4=%v v6=%v)", v4.IsValid(), v6.IsValid())
	return nil
}

func RemoveTunnelService() error {
	key := tunnelServiceKey()
	out, err := runScutil("remove " + key + "/IPv4\nremove " + key + "/IPv6\nquit\n")
	if err != nil {
		return err
	}
	if out = onlyScutilErrors(out); out != "" {
		return fmt.Errorf("scutil remove tunnel service: %s", out)
	}
	return nil
}

// PurgeSystemState removes the DNS and tunnel service entries tunnels publish. A
// daemon that exits without closing its tunnels leaves them behind, and the stale
// service keeps a utun that no longer exists as the primary network.
func PurgeSystemState() error {
	err := errors.Join(RemoveTunnelService(), removeGlobalDNS())
	_ = removeResolverFiles()
	removeFakeDNSRoutes()
	return err
}

// fakeDNSAddrs are TunnelDnsConfig's default FakeDNS addresses, from ranges reserved for
// benchmarking and documentation.
var fakeDNSAddrs = []string{"198.18.0.2", "2001:db8::53"}

// removeFakeDNSRoutes drops a route to the FakeDNS addresses left on a physical interface.
func removeFakeDNSRoutes() {
	for _, a := range fakeDNSAddrs {
		inet := "-inet"
		if strings.Contains(a, ":") {
			inet = "-inet6"
		}
		out, err := exec.Command("route", "-n", "get", inet, a).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "destination: "+a) || onTunnelIface(string(out)) {
			continue
		}
		_ = exec.Command("route", "-q", "-n", "delete", inet, "-host", a).Run()
	}
}

func onTunnelIface(routeGet string) bool {
	for _, line := range strings.Split(routeGet, "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			name = strings.TrimSpace(name)
			return strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "wgtun")
		}
	}
	return false
}

// onlyScutilErrors drops the "No such key" lines a remove of a missing key prints.
func onlyScutilErrors(out string) string {
	var errs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "No such key" {
			errs = append(errs, line)
		}
	}
	return strings.Join(errs, "; ")
}

func removeResolverFiles() error {
	entries, err := os.ReadDir(resolverDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), resolverPrefix) {
			_ = os.Remove(resolverDir + "/" + e.Name())
		}
	}
	return nil
}

func runScutil(script string) (string, error) {
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func writeScutilString(b *strings.Builder, v string) {
	if v == "" || strings.ContainsAny(v, " \t\n\"") {
		b.WriteString(strconv.Quote(v))
		return
	}
	b.WriteString(v)
}

func dnsFromIPConfig(ifName string) []string {
	out, err := exec.Command("ipconfig", "getpacket", ifName).CombinedOutput()
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "domain_name_server") {
			continue
		}
		_, rest, ok := strings.Cut(line, "{")
		if !ok {
			continue
		}
		rest, _, _ = strings.Cut(rest, "}")
		for _, p := range strings.Split(rest, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := netip.ParseAddr(p); err == nil {
				servers = append(servers, net.JoinHostPort(p, "53"))
			}
		}
	}
	return servers
}

// dnsFromScutil reads configd's resolvers when DHCP has none, as with a static or IPv6
// only setup. The interface's scoped resolver is its own DNS. The general list also holds
// supplemental resolvers, which match only some domains and include the tunnel's own DNS
// while one is up, so those are skipped.
func dnsFromScutil(ifName string) []string {
	out, err := exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput()
	if err != nil {
		return nil
	}
	return pickScutilDNS(parseScutilDNS(string(out)), ifName)
}

type scutilResolver struct {
	scoped       bool
	ifName       string
	domain       bool
	supplemental bool
	servers      []string
}

func parseScutilDNS(out string) []scutilResolver {
	var resolvers []scutilResolver
	scoped := false
	var cur *scutilResolver
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trim, "DNS configuration"):
			scoped = strings.Contains(trim, "scoped queries")
			cur = nil
		case strings.HasPrefix(trim, "resolver #"):
			resolvers = append(resolvers, scutilResolver{scoped: scoped})
			cur = &resolvers[len(resolvers)-1]
		case cur == nil:
		default:
			key, val, ok := strings.Cut(trim, ":")
			if !ok {
				continue
			}
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			switch {
			case strings.HasPrefix(key, "nameserver["):
				if ip, err := netip.ParseAddr(val); err == nil {
					cur.servers = append(cur.servers, net.JoinHostPort(ip.String(), "53"))
				}
			case key == "if_index":
				if _, name, ok := strings.Cut(val, "("); ok {
					cur.ifName = strings.TrimSuffix(name, ")")
				}
			case key == "domain":
				cur.domain = true
			case key == "flags":
				cur.supplemental = strings.Contains(val, "Supplemental")
			}
		}
	}
	return resolvers
}

func pickScutilDNS(resolvers []scutilResolver, ifName string) []string {
	if ifName != "" {
		for _, r := range resolvers {
			if r.scoped && r.ifName == ifName && len(r.servers) > 0 {
				return r.servers
			}
		}
	}
	var servers []string
	seen := map[string]bool{}
	for _, r := range resolvers {
		if r.scoped || r.supplemental || r.domain {
			continue
		}
		n := strings.ToLower(r.ifName)
		if strings.HasPrefix(n, "utun") || strings.HasPrefix(n, "wgtun") {
			continue
		}
		for _, hp := range r.servers {
			if !seen[hp] {
				seen[hp] = true
				servers = append(servers, hp)
			}
		}
	}
	return servers
}
