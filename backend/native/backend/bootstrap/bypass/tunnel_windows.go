//go:build windows

package bypass

const tunnelOnlyDNS = false

func bindTunnelSocket(fd uintptr) error {
	return bindToInterface(fd, CurrentTunnelInterfaceIndex())
}
