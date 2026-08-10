package bypass

import (
	"net"
	"syscall"
)

// SocketBypass marks/protects a socket so it is excluded from the tunnel
type SocketBypass func(fd uintptr) error

// NewBypassDialer applies bypass to every outbound socket.
func NewBypassDialer(fn SocketBypass) *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			if fn == nil {
				return nil
			}
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = fn(fd)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
}
