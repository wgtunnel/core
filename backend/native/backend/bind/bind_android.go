//go:build android

package bind

/*
#cgo LDFLAGS: -llog -landroid
#include <stdint.h>
extern int bypass_socket(int fd);
*/
import "C"
import (
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/wgtunnel/backend/log"
)

// NewBind protects the socket via VpnService.protect when bypass is set, so
// its traffic doesn't loop back into the tunnel, otherwise it's a plain bind.
func NewBind(bypass bool) conn.Bind {
	if bypass {
		return conn.NewStdNetBindWithControl(protectControlFunc)
	}
	return conn.NewStdNetBind()
}

func protectControlFunc(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		if C.bypass_socket(C.int(fd)) == 0 {
			opErr = syscall.EACCES
			log.Error("Protect", "Failed to protect socket FD: %d", fd)
		} else {
			log.Debug("Protect", "Protected socket FD: %d", fd)
		}
	})
	if err != nil {
		return err
	}
	return opErr
}
