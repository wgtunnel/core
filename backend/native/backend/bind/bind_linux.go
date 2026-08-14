//go:build linux && !android

package bind

import (
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/vpn/firewall/mark"
)

const tag = "Bind"

// NewBind marks every UDP socket with the tunnel bypass fwmark so handshake
// and data packets are accepted by the kill switch.
func NewBind() conn.Bind {
	return conn.NewStdNetBindWithControl(bypassControlFunc)
}

func bypassControlFunc(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark.LinuxBypassMarkNum)
		if opErr != nil {
			log.Error(tag, "Failed to mark socket FD %d: %v", fd, opErr)
			return
		}
		log.Debug(tag, "Marked socket FD %d with bypass fwmark", fd)
	})
	if err != nil {
		return err
	}
	return opErr
}
