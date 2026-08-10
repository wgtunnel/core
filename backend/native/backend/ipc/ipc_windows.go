//go:build windows

package ipc

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/wgtunnel/backend/log"
)

func SetupIPC(name string, uapiPath string) (net.Listener, error) {
	uapi, err := ipc.UAPIListen(name)
	if err != nil {
		log.Error("IPC", "UAPIListen: %v", err)
		return nil, err
	}

	return uapi, nil
}
