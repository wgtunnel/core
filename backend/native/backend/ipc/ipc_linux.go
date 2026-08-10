//go:build linux && !android

package ipc

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/wgtunnel/backend/log"
)

func SetupIPC(name string, uapiPath string) (net.Listener, error) {

	uapiFile, err := ipc.UAPIOpen(uapiPath, name)
	if err != nil {
		log.Error("IPC", "UAPIOpen: %v", err)
		return nil, err
	}

	uapi, err := ipc.UAPIListen(uapiPath, name, uapiFile)
	if err != nil {
		uapiFile.Close()
		log.Error("IPC", "UAPIListen: %v", err)
		return nil, err
	}

	return uapi, nil
}
