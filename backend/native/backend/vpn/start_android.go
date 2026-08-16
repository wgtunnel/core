//go:build android

package vpn

import "C"
import (
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/wgtunnel/backend/log"
	"golang.org/x/sys/unix"
)

//export startVpn
func startVpn(
	handle int32,
	ifName string,
	tunFd int32,
	config string,
	dnsConfig string,
	uapiPath string,
) int32 {
	realTUN, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		_ = unix.Close(int(tunFd))
		log.Error(tag, "CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}
	_ = name
	return startVpnDevice(
		handle,
		ifName,
		realTUN,
		config,
		dnsConfig,
		uapiPath,
	)
}

func OnTunnelStopped(id int32) {
	//no-op, desktop
}
