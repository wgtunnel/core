//go:build linux

package linux

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/wgtunnel/backend/log"
)

const (
	ResolvConfPath = "/etc/resolv.conf"
	ResolvConfBak  = "/var/lib/wgtunnel/resolv.conf.bak"
)

const tag = "Resolv"

// BackupResolvConf copies resolv.conf to the backup path if no backup exists yet.
func BackupResolvConf() error {
	if _, err := os.Stat(ResolvConfBak); err == nil {
		log.Debug(tag, "resolv.conf backup already exists, skipping")
		return nil
	}
	src, err := os.ReadFile(ResolvConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", ResolvConfPath, err)
	}
	if err := os.WriteFile(ResolvConfBak, src, 0644); err != nil {
		return fmt.Errorf("write backup %s: %w", ResolvConfBak, err)
	}
	log.Debug(tag, "Backup created at %s", ResolvConfBak)
	return nil
}

// WriteResolveConf overwrites /etc/resolv.conf with the given nameservers and search domains.
// It creates a single backup first.
func WriteResolvConf(servers []netip.Addr, searchDomains []string) error {
	log.Debug(tag, "DNS resolv.conf fallback mode...")
	if err := BackupResolvConf(); err != nil {
		log.Error(tag, "Backup failed: %v", err)
		// continue anyway; still attempt write
	}

	f, err := os.Create(ResolvConfPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", ResolvConfPath, err)
	}
	defer f.Close()

	for _, d := range servers {
		if _, err := fmt.Fprintf(f, "nameserver %s\n", d.String()); err != nil {
			return fmt.Errorf("write nameserver: %w", err)
		}
	}
	if len(searchDomains) > 0 {
		if _, err := fmt.Fprintf(f, "search %s\n", strings.Join(searchDomains, " ")); err != nil {
			return fmt.Errorf("write search: %w", err)
		}
	}
	log.Error(tag, "Wrote %d nameservers to %s", len(servers), ResolvConfPath)
	return nil
}

// RestoreResolvConf restores resolv.conf from backup if present.
func RestoreResolvConf() error {
	if _, err := os.Stat(ResolvConfBak); os.IsNotExist(err) {
		log.Debug(tag, "No resolv.conf backup to restore")
		return nil
	}
	src, err := os.ReadFile(ResolvConfBak)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	if err := os.WriteFile(ResolvConfPath, src, 0644); err != nil {
		return fmt.Errorf("restore %s: %w", ResolvConfPath, err)
	}
	_ = os.Remove(ResolvConfBak)
	log.Debug(tag, "Restored original %s from backup", ResolvConfPath)
	return nil
}

// ResolvConfBackupExists reports whether a backup file is present.
func ResolvConfBackupExists() bool {
	_, err := os.Stat(ResolvConfBak)
	return err == nil
}

// UnderlayResolvConfServers reads the network's own nameservers from resolv.conf, for systems
// where neither systemd-resolved nor NetworkManager manages DNS. While a tunnel's DNS is
// written there, the original is in the backup. Loopback stubs are left out as their upstream
// queries would follow the tunnel's routes, not the bypass.
func UnderlayResolvConfServers() []string {
	path := ResolvConfPath
	if ResolvConfBackupExists() {
		path = ResolvConfBak
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseNameservers(string(data))
}

func parseNameservers(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.IsLoopback() || addr.IsUnspecified() {
			continue
		}
		out = append(out, netip.AddrPortFrom(addr, 53).String())
	}
	return out
}
