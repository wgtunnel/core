//go:build windows

package bypass

func bindTunnelSocket(fd uintptr) error {
	return bindToInterface(fd, CurrentTunnelInterfaceIndex())
}
