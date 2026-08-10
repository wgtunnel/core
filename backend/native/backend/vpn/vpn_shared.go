package vpn

/*
#include "vpn_jni.h"
*/
import "C"

import (
	"net"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"github.com/wgtunnel/backend/bind"
	"github.com/wgtunnel/backend/constants"
	hand "github.com/wgtunnel/backend/handle"
	"github.com/wgtunnel/backend/ipc"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/roaming"
	"github.com/wgtunnel/backend/tunwrap"
)

const tag = "VpnBackend"

type TunnelHandle struct {
	device *device.Device
	uapi   net.Listener
}

var (
	tunnelHandles    = make(map[int32]TunnelHandle)
	lastTunnelStatus sync.Map
	tunnelMu         sync.RWMutex
)

// startDevice assumes tun is already created
// Bind and roaming come from platform files
func startVpnDevice(
	interfaceName string,
	baseTun tun.Device,
	settings string,
	dnsConfigJSON string,
	uapiPath string,
) int32 {
	log.Debug(tag, "DNS config passed: %s", dnsConfigJSON)

	tun, err := tunwrap.MaybeWrapTUN(baseTun, dnsConfigJSON)
	if err != nil {
		// MaybeWrapTUN should close rawTUN on failure
		log.Error(tag, "DNS wrap: %v", err)
		return -1
	}

	conf, err := wireproxyawg.ParseConfigString(settings)
	if err != nil {
		log.Error(tag, "Invalid config file", err)
		tun.Close()
		return -1
	}

	tunHandle, err := hand.GenerateUniqueHandle()
	if err != nil {
		log.Error(tag, "Unable to generate handle: %v", err)
		tun.Close()
		return -1
	}

	statusCB := func(code device.StatusCode) {
		key := tunHandle
		if prev, loaded := lastTunnelStatus.LoadOrStore(key, code); loaded {
			if prev == code {
				return
			}
			lastTunnelStatus.Store(key, code)
		}
		go C.notifyStatus(C.int32_t(tunHandle), C.int32_t(code))
	}

	tunDevice := device.NewDevice(
		tun,
		bind.NewBind(),
		log.WithTag("VpnTun/"+interfaceName).DeviceLogger(),
		statusCB,
	)

	roaming.ApplyRoaming(tunDevice)

	ipcRequest, err := wireproxyawg.CreateIPCRequest(conf.Device, false)
	if err != nil {
		log.Error(tag, "CreateIPCRequest: %v", err)
		hand.ReleaseHandle(tunHandle)
		tunDevice.Close()
		return -1
	}

	if err := tunDevice.IpcSet(ipcRequest.IpcRequest); err != nil {
		log.Error(tag, "IpcSet: %v", err)
		hand.ReleaseHandle(tunHandle)
		tunDevice.Close()
		return -1
	}

	tunName, _ := tun.Name()

	var uapi net.Listener
	uapi, err = ipc.SetupIPC(tunName, uapiPath)
	if err != nil {
		log.Error(tag, "SetupIPC: %v", err)
	} else if uapi != nil {
		go func() {
			for {
				connection, err := uapi.Accept()
				if err != nil {
					return
				}
				go tunDevice.IpcHandle(connection)
			}
		}()
	}

	if err := tunDevice.Up(); err != nil {
		log.Error(tag, "Unable to bring up device: %v", err)
		if uapi != nil {
			uapi.Close()
		}
		hand.ReleaseHandle(tunHandle)
		tunDevice.Close()
		return -1
	}

	log.Debug(tag, "Tunnel started successfully for handle %d", tunHandle)
	tunnelMu.Lock()
	tunnelHandles[tunHandle] = TunnelHandle{device: tunDevice, uapi: uapi}
	tunnelMu.Unlock()
	return tunHandle
}

//export updateVpnTunnelPeers
func updateVpnTunnelPeers(handle int32, settings string) int32 {
	tunnelMu.RLock()
	tunHandle, ok := tunnelHandles[handle]
	tunnelMu.RUnlock()
	if !ok {
		log.Error(tag, "Tunnel is not up")
		return -1
	}

	conf, err := wireproxyawg.ParseConfigString(settings)
	if err != nil {
		log.Error(tag, "Invalid config file", err)
		return -1
	}

	ipcRequest, err := wireproxyawg.CreatePeerIPCRequest(conf.Device)
	if err != nil {
		log.Error(tag, "CreateIPCRequest: %v", err)
		return -1
	}

	if err := tunHandle.device.IpcSet(ipcRequest.IpcRequest); err != nil {
		log.Error(tag, "IpcSet: %v", err)
		return -1
	}

	log.Debug(tag, "Configuration updated successfully with handle %d", handle)
	return 0
}

//export stopVpn
func stopVpn(handle int32) {
	tunnelMu.Lock()
	tunHandle, ok := tunnelHandles[handle]
	if !ok {
		tunnelMu.Unlock()
		log.Error(tag, "Tunnel is not up")
		return
	}
	delete(tunnelHandles, handle)
	tunnelMu.Unlock()

	if tunHandle.uapi != nil {
		tunHandle.uapi.Close()
	}
	if tunHandle.device != nil {
		tunHandle.device.Close()
	}
	lastTunnelStatus.Delete(handle)
	OnTunnelStopped(handle)
	hand.ReleaseHandle(handle)
	C.notifyStatus(C.int32_t(handle), C.int32_t(constants.StatusStop))
}

//export getVpnConfig
func getVpnConfig(handle int32) *C.char {
	tunnelMu.RLock()
	tunHandle, ok := tunnelHandles[handle]
	tunnelMu.RUnlock()
	if !ok {
		return nil
	}
	settings, err := tunHandle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export version
func version() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/amnezia-vpn/amneziawg-go" ||
			strings.HasPrefix(dep.Path, "github.com/amnezia-vpn/amneziawg-go/") {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}
