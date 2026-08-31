package bypass

import (
	"net"
	"sync/atomic"

	"github.com/wgtunnel/backend/log"
)

var tunnelIfIndex atomic.Uint32

func SetTunnelInterfaceIndex(idx uint32) {
	tunnelIfIndex.Store(idx)
	log.Debug("TunnelDialer", "tunnel ifIndex=%d", idx)
}

func SetTunnelInterfaceIndexFromName(name string) {
	if name == "" {
		SetTunnelInterfaceIndex(0)
		return
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Debug("TunnelDialer", "InterfaceByName %q: %v", name, err)
		return
	}
	SetTunnelInterfaceIndex(uint32(iface.Index))
}

func CurrentTunnelInterfaceIndex() uint32 {
	return tunnelIfIndex.Load()
}
