//go:build darwin

package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/wgtunnel/backend/log"
	"golang.org/x/net/nettest"
)

const (
	tag               = "SetDNS"
	macOSGlobalDNSKey = "State:/Network/Service/FF457792-79C0-4A25-8392-D875BBEACCA6/DNS"
	resolverDir       = "/etc/resolver"
	resolverPrefix    = "wgtunnel."
)

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
	_ = iface
	if len(servers) == 0 && len(searchDomains) == 0 {
		log.Debug(tag, "Skipping DNS apply (empty)")
		return nil
	}
	if fullTunnel && len(servers) > 0 {
		if err := setGlobalDNS(servers, searchDomains); err != nil {
			return err
		}
		_ = removeResolverFiles()
		log.Debug(tag, "Configured global DNS via scutil (servers=%d search=%d)", len(servers), len(searchDomains))
		return nil
	}
	_ = removeGlobalDNS()
	if err := writeResolverFiles(servers, searchDomains); err != nil {
		return err
	}
	log.Debug(tag, "Configured split DNS via /etc/resolver")
	return nil
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
	return dnsFromScutil(), nil
}

func setGlobalDNS(servers []netip.Addr, search []string) error {
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString("d.add SearchOrder # 100000\n")
	script.WriteString("d.add ServerAddresses *")
	for _, ip := range servers {
		if ip.Is6() && !nettest.SupportsIPv6() {
			continue
		}
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
	script.WriteString(macOSGlobalDNSKey)
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
	out, err := runScutil("remove " + macOSGlobalDNSKey + "\nquit\n")
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "No such key" {
		return nil
	}
	return fmt.Errorf("scutil remove: %s", out)
}

func writeResolverFiles(servers []netip.Addr, search []string) error {
	if err := os.MkdirAll(resolverDir, 0755); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# wgtunnel split DNS\n")
	for _, ip := range servers {
		buf.WriteString("nameserver ")
		buf.WriteString(ip.String())
		buf.WriteString("\n")
	}
	if len(search) > 0 {
		buf.WriteString("search")
		for _, d := range search {
			buf.WriteByte(' ')
			buf.WriteString(strings.TrimSuffix(d, "."))
		}
		buf.WriteByte('\n')
	}
	path := resolverDir + "/" + resolverPrefix + "search"
	return os.WriteFile(path, buf.Bytes(), 0644)
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

func dnsFromScutil() []string {
	out, err := exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput()
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	skipBlock := false
	for _, line := range strings.Split(string(out), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "resolver #") {
			skipBlock = false
			continue
		}
		if strings.Contains(trim, "if_index") && (strings.Contains(trim, "utun") || strings.Contains(trim, "wgtun")) {
			skipBlock = true
			continue
		}
		if skipBlock {
			continue
		}
		if strings.HasPrefix(trim, "nameserver[") {
			_, rest, ok := strings.Cut(trim, ":")
			if !ok {
				continue
			}
			ip := strings.TrimSpace(rest)
			if _, err := netip.ParseAddr(ip); err != nil {
				continue
			}
			hp := net.JoinHostPort(ip, "53")
			if seen[hp] {
				continue
			}
			seen[hp] = true
			servers = append(servers, hp)
		}
	}
	return servers
}
