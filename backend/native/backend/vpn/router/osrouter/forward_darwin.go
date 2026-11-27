//go:build darwin

package osrouter

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/wgtunnel/backend/instance"
	"github.com/wgtunnel/backend/log"
)

// forwardAnchor holds NAT and MSS clamping for traffic macOS forwards into the tunnel, such
// as a VM on Apple's shared network (UTM, Tart, Lima, Docker's VZ backend). Internet Sharing
// only NATs on the physical interface, so a guest's packets entered the tunnel with their
// private source, which a WireGuard server drops, and with the guest's MSS, which is too big
// for the tunnel MTU and stalls TCP. Translation and scrub rules only run in anchors the main
// ruleset calls, which for the system's own pf.conf means com.apple/*.
func forwardAnchor() string { return "com.apple/" + instance.Name() + "-forward" }

func forwardRules(iface string, mtu int) string {
	var b strings.Builder
	if mtu > 0 {
		fmt.Fprintf(&b, "scrub on %s inet all max-mss %d\n", iface, mtu-40)
		fmt.Fprintf(&b, "scrub on %s inet6 all max-mss %d\n", iface, mtu-60)
	}
	// The host's own traffic already has the tunnel address, so only forwarded packets match.
	fmt.Fprintf(&b, "nat on %s inet from ! (%s) to any -> (%s:0)\n", iface, iface, iface)
	fmt.Fprintf(&b, "nat on %s inet6 from ! (%s) to any -> (%s:0)\n", iface, iface, iface)
	return b.String()
}

func loadForwardRules(iface string, mtu int) error {
	cmd := exec.Command("pfctl", "-a", forwardAnchor(), "-f", "-")
	cmd.Stdin = strings.NewReader(forwardRules(iface, mtu))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %v (%s)", forwardAnchor(), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PurgeForwarding drops the forwarding rules a tunnel loaded. A daemon that exits without
// closing its tunnels leaves them on a utun that no longer exists, where another VPN's utun
// could later take the name.
func PurgeForwarding() {
	if out, err := exec.Command("pfctl", "-a", forwardAnchor(), "-F", "all").CombinedOutput(); err != nil {
		log.Debug(tag, "flush %s: %v (%s)", forwardAnchor(), err, strings.TrimSpace(string(out)))
	}
}
