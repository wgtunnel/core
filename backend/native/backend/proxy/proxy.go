package proxy

/*
#include "vpn_jni.h"
*/
import "C"
import (
	"context"
	"net"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	binder "github.com/wgtunnel/backend/bind"
	"github.com/wgtunnel/backend/constants"
	handlepkg "github.com/wgtunnel/backend/handle"
	"github.com/wgtunnel/backend/ipc"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/roaming"
	"github.com/wgtunnel/backend/statusnotify"
	"github.com/wgtunnel/backend/tunwrap"
)

const tag = "ProxyBackend"

var (
	cancelFuncs          map[int32]context.CancelFunc
	virtualTunnelHandles map[int32]*wireproxyawg.VirtualTun
	tunnelMu             sync.RWMutex
)

func init() {
	virtualTunnelHandles = make(map[int32]*wireproxyawg.VirtualTun)
	cancelFuncs = make(map[int32]context.CancelFunc)
}

//export startProxy
// startProxy uses an already allocated handle so Kotlin can map status before start.
// On failure the handle stays reserved — the caller must release it.
// On success ownership transfers to the tunnel map and turnProxyTunnelOff releases it.
func startProxy(handle int32, ifName string, config string, uapiPath string, bypass int32, dnsConfig string) int32 {
	if handle < 0 || !handlepkg.IsReserved(handle) {
		log.Error(tag, "startProxy: invalid/unreserved handle %d", handle)
		return -1
	}

	conf, err := wireproxyawg.ParseConfigString(config)
	if err != nil {
		log.Error(tag, "Invalid config file", err)
		return -1
	}

	setting, err := wireproxyawg.CreateIPCRequest(conf.Device, false)
	if err != nil {
		log.Error(tag, "Create IPC request failed")
		return -1
	}

	tun, tnet, err := netstack.CreateNetTUN(
		setting.DeviceAddr,
		setting.DNS,
		setting.MTU,
	)
	if err != nil {
		log.Error(tag, "Create TUN failed")
		return -1
	}

	deviceTUN, err := tunwrap.MaybeWrapTUNDial(tun, dnsConfig, tnet.DialContext)
	if err != nil {
		log.Error(tag, "DNS wrap: %v", err)
		_ = tun.Close()
		return -1
	}

	tunName, err := tun.Name()
	if err != nil {
		log.Error(tag, "Failed to get TUN name: %v", err)
		_ = deviceTUN.Close()
		return -1
	}

	var bind conn.Bind
	if bypass == 1 {
		bind = binder.NewBind()
	} else {
		bind = conn.NewStdNetBind()
	}

	statusCB := func(code device.StatusCode) {
		// Report to Kotlin with at-least-once delivery until Kotlin acks.
		statusnotify.Report(handle, int32(code))
	}

	tunDevice := device.NewDevice(
		deviceTUN,
		bind,
		log.WithTag("ProxyTun/"+ifName).DeviceLogger(),
		statusCB,
	)

	roaming.ApplyRoaming(tunDevice)

	if err = tunDevice.IpcSet(setting.IpcRequest); err != nil {
		log.Error(tag, "Ipc setting failed")
		tunDevice.Close()
		return -1
	}

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

	if err = tunDevice.Up(); err != nil {
		log.Error(tag, "Failed to bring up device")

		if uapi != nil {
			uapi.Close()
		}
		tunDevice.Close()
		return -1
	}

	virtualTun := &wireproxyawg.VirtualTun{
		Tnet:           tnet,
		Dev:            tunDevice,
		Logger:         log.WithTag("Proxy").DeviceLogger(),
		Uapi:           uapi,
		Conf:           conf.Device,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	tunnelMu.Lock()
	virtualTunnelHandles[handle] = virtualTun
	cancelFuncs[handle] = tunnelCancel
	tunnelMu.Unlock()

	for _, spawner := range conf.Routines {
		go func(s wireproxyawg.RoutineSpawner) {
			if err := s.SpawnRoutine(tunnelCtx, virtualTun); err != nil {
				log.Error(tag, "Routine failed: %v", err)
			}
		}(spawner)
	}

	log.Debug(tag, "Started proxy tunnel for handle %d", handle)

	return 0
}

//export updateProxyTunnelPeers
func updateProxyTunnelPeers(tunnelHandle int32, settings string) int32 {
	tunnelMu.RLock()
	virtualTun, ok := virtualTunnelHandles[tunnelHandle]
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

	err = virtualTun.Dev.IpcSet(ipcRequest.IpcRequest)
	if err != nil {
		log.Error(tag, "IpcSet: %v", err)
		return -1
	}

	log.Debug(tag, "Configuration updated successfully")
	return 0
}

//export getProxyConfig
func getProxyConfig(tunnelHandle int32) *C.char {
	tunnelMu.RLock()
	handle, ok := virtualTunnelHandles[tunnelHandle]
	tunnelMu.RUnlock()
	if !ok {
		log.Error(tag, "Tunnel is not up")
		return nil
	}
	settings, err := handle.Dev.IpcGet()
	if err != nil {
		log.Error(tag, "Failed to get device config: %v", err)
		return nil
	}
	return C.CString(settings)
}

//export turnProxyTunnelOff
func turnProxyTunnelOff(virtualTunnelHandle int32) {

	tunnelMu.Lock()

	virtualTun, ok := virtualTunnelHandles[virtualTunnelHandle]
	if !ok {
		tunnelMu.Unlock()

		log.Error(
			tag,
			"Tunnel handle %d not found",
			virtualTunnelHandle,
		)
		return
	}

	cancel := cancelFuncs[virtualTunnelHandle]

	delete(virtualTunnelHandles, virtualTunnelHandle)
	delete(cancelFuncs, virtualTunnelHandle)

	tunnelMu.Unlock()

	log.Debug(
		tag,
		"Tearing down tunnel %d",
		virtualTunnelHandle,
	)

	if cancel != nil {
		cancel()
	}

	if virtualTun.Uapi != nil {
		virtualTun.Uapi.Close()
	}

	if virtualTun.Dev != nil {
		virtualTun.Dev.Close()
	}

	statusnotify.Clear(virtualTunnelHandle)
	handlepkg.ReleaseHandle(virtualTunnelHandle)

	statusnotify.NotifyOnce(virtualTunnelHandle, int32(constants.StatusStop))

	log.Debug(
		tag,
		"Tunnel handle %d fully closed",
		virtualTunnelHandle,
	)
}
