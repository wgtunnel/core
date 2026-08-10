//go:build android

package ipc

import (
	"net"

	awgipc "github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/wgtunnel/backend/log"
)

func SetupIPC(name string, uapiPath string) (net.Listener, error) {
	uapiFile, err := awgipc.UAPIOpen(uapiPath, name)
	if err != nil {
		log.Error("IPC", "UAPIOpen: %v", err)
		return nil, err
	}

	uapi, err := awgipc.UAPIListen(uapiPath, name, uapiFile)
	if err != nil {
		_ = uapiFile.Close()
		log.Error("IPC", "UAPIListen: %v", err)
		return nil, err
	}
	return uapi, nil
}
