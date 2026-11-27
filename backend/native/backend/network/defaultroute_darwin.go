//go:build darwin

package network

import (
	"net"
	"os/exec"
	"strings"
)

// PhysicalDefault is the underlay default route, ignoring leftover utun defaults.
type PhysicalDefault struct {
	Gateway string
	IfName  string
	IfIndex uint32
}

func LookupPhysicalDefault4() PhysicalDefault {
	return lookupPhysicalDefault("default", "inet")
}

func LookupPhysicalDefault6() PhysicalDefault {
	return lookupPhysicalDefault("-inet6", "inet6")
}

func lookupPhysicalDefault(getArg, netstatFamily string) PhysicalDefault {
	if d := fromRouteGet(getArg); d.IfName != "" {
		return d
	}
	return fromNetstat(netstatFamily, nwiRanking(netstatFamily))
}

// nwiRanking is configd's interface order from `scutil --nwi`. While a full tunnel
// holds the primary slot every physical default is scoped, and this order
// names the physical network macOS uses
func nwiRanking(family string) []string {
	out, err := exec.Command("/usr/sbin/scutil", "--nwi").CombinedOutput()
	if err != nil {
		return nil
	}
	return parseNWIRanking(string(out), family)
}

func parseNWIRanking(out, family string) []string {
	header := "IPv4 network interface information"
	if family == "inet6" {
		header = "IPv6 network interface information"
	}
	var ranked []string
	in := false
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trim, header):
			in = true
		case !in:
		case strings.HasPrefix(trim, "REACH"), strings.HasSuffix(trim, "network interface information"):
			return ranked
		default:
			if name, rest, ok := strings.Cut(trim, ":"); ok && strings.HasPrefix(strings.TrimSpace(rest), "flags") {
				ranked = append(ranked, strings.TrimSpace(name))
			}
		}
	}
	return ranked
}

func fromRouteGet(getArg string) PhysicalDefault {
	args := []string{"-n", "get"}
	if getArg == "-inet6" {
		args = append(args, "-inet6", "default")
	} else {
		args = append(args, "default")
	}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return PhysicalDefault{}
	}
	var gw, ifName string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			gw = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		case strings.HasPrefix(line, "interface:"):
			ifName = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if ifName == "" || isTunnelIface(ifName) {
		return PhysicalDefault{}
	}
	return withIndex(gw, ifName)
}

// fromNetstat picks the physical default route, preferring the highest ranked
// interface when there are several. Without a ranking it takes netstat's first.
func fromNetstat(family string, ranking []string) PhysicalDefault {
	args := []string{"-rn"}
	if family != "" {
		args = append(args, "-f", family)
	}
	out, err := exec.Command("netstat", args...).CombinedOutput()
	if err != nil {
		return PhysicalDefault{}
	}
	gw, ifName := pickNetstatDefault(string(out), ranking)
	if ifName == "" {
		return PhysicalDefault{}
	}
	return withIndex(gw, ifName)
}

func pickNetstatDefault(out string, ranking []string) (gw, ifName string) {
	gateways := map[string]string{}
	var order []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		g, netif := fields[1], fields[len(fields)-1]
		if isTunnelIface(netif) || strings.HasPrefix(g, "link#") {
			continue
		}
		if _, seen := gateways[netif]; !seen {
			gateways[netif] = g
			order = append(order, netif)
		}
	}
	for _, name := range ranking {
		if g, ok := gateways[name]; ok {
			return g, name
		}
	}
	if len(order) > 0 {
		return gateways[order[0]], order[0]
	}
	return "", ""
}

func withIndex(gw, ifName string) PhysicalDefault {
	d := PhysicalDefault{Gateway: gw, IfName: ifName}
	if iface, err := net.InterfaceByName(ifName); err == nil {
		d.IfIndex = uint32(iface.Index)
	}
	return d
}
