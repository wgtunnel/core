//go:build unix && !android

package bypass

func bindTunnelSocket(fd uintptr) error {
	return bindToDevice(fd, CurrentTunnelInterfaceIndex())
}
