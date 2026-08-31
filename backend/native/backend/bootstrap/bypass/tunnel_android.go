//go:build android

package bypass

/*
#cgo LDFLAGS: -landroid
#include <android/multinetwork.h>
*/
import "C"
import (
	"fmt"
	"syscall"

	"github.com/wgtunnel/backend/log"
)

func bindTunnelSocket(fd uintptr) error {
	handle := CurrentVpnNetworkHandle()
	if handle == 0 {
		return nil
	}
	rc := C.android_setsocknetwork(C.net_handle_t(handle), C.int(fd))
	if rc != 0 {
		err := syscall.Errno(-rc)
		log.Debug("TunnelDialer", "android_setsocknetwork handle=%d fd=%d: %v", handle, fd, err)
		return fmt.Errorf("android_setsocknetwork: %w", err)
	}
	log.Debug("TunnelDialer", "bound fd=%d to vpn handle=%d", fd, handle)
	return nil
}
