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
	return fromNetstat(netstatFamily)
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

func fromNetstat(family string) PhysicalDefault {
	args := []string{"-rn"}
	if family != "" {
		args = append(args, "-f", family)
	}
	out, err := exec.Command("netstat", args...).CombinedOutput()
	if err != nil {
		return PhysicalDefault{}
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		gw, netif := fields[1], fields[len(fields)-1]
		if isTunnelIface(netif) || strings.HasPrefix(gw, "link#") {
			continue
		}
		return withIndex(gw, netif)
	}
	return PhysicalDefault{}
}

func withIndex(gw, ifName string) PhysicalDefault {
	d := PhysicalDefault{Gateway: gw, IfName: ifName}
	if iface, err := net.InterfaceByName(ifName); err == nil {
		d.IfIndex = uint32(iface.Index)
	}
	return d
}
