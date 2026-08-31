//go:build android

package bypass

/*
#include <stdint.h>
*/
import "C"
import (
	"sync/atomic"

	"github.com/wgtunnel/backend/log"
)

var vpnNetworkHandle atomic.Int64

//export setVpnNetworkHandle
func setVpnNetworkHandle(handle int64) {
	vpnNetworkHandle.Store(handle)
	log.Debug("TunnelDialer", "vpn network handle=%d", handle)
}

func CurrentVpnNetworkHandle() int64 {
	return vpnNetworkHandle.Load()
}
