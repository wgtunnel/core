//go:build unix && !android

package bypass

const tunnelOnlyDNS = false

func bindTunnelSocket(fd uintptr) error {
	return bindToDevice(fd, CurrentTunnelInterfaceIndex())
}
