//go:build android

package local

/*
#include <stdint.h>
*/
import "C"
import (
	"sync/atomic"

	"github.com/wgtunnel/backend/log"
)

var underlayNetworkHandle atomic.Int64

//export setUnderlayNetworkHandle
func setUnderlayNetworkHandle(handle int64) {
	underlayNetworkHandle.Store(handle)
	log.Debug("LocalDNS", "underlay network handle=%d", handle)
}

func CurrentUnderlayNetworkHandle() int64 {
	return underlayNetworkHandle.Load()
}
