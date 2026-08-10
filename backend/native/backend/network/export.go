//go:build cgo && !android

package network

/*
#include <stdint.h>
#include <stdlib.h>
extern void NotifyNetworkInfo(const char* json);
*/
import "C"
import (
	"encoding/json"
	"sync"
	"unsafe"
)

var (
	monitorMu sync.Mutex
	monitor   Monitor
)

type networkInfoDTO struct {
	Type          string   `json:"type"`
	InterfaceName string   `json:"interfaceName"`
	IfIndex       uint32   `json:"ifIndex"`
	SSID          string   `json:"ssid"`
	BSSID         string   `json:"bssid"`
	HasIPv4       bool     `json:"hasIpv4"`
	HasIPv6       bool     `json:"hasIpv6"`
	DNSServers    []string `json:"dnsServers"`
}

func toDTO(info NetworkInfo) networkInfoDTO {
	typeStr := "disconnected"
	switch info.Type {
	case NetworkWifi:
		typeStr = "wifi"
	case NetworkEthernet:
		typeStr = "ethernet"
	case NetworkOther:
		typeStr = "other"
	}
	return networkInfoDTO{
		Type:          typeStr,
		InterfaceName: info.InterfaceName,
		IfIndex:       info.IfIndex,
		SSID:          info.SSID,
		BSSID:         info.BSSID,
		HasIPv4:       info.HasIPv4,
		HasIPv6:       info.HasIPv6,
		DNSServers:    info.DNSServers,
	}
}

func infoJSON(info NetworkInfo) string {
	b, _ := json.Marshal(toDTO(info))
	return string(b)
}

func emit(info NetworkInfo) {
	c := C.CString(infoJSON(info))
	C.NotifyNetworkInfo(c)
	C.free(unsafe.Pointer(c))
}

//export startNetworkMonitor
func startNetworkMonitor() C.int {
	monitorMu.Lock()
	if monitor != nil {
		monitorMu.Unlock()
		return 0
	}
	monitorMu.Unlock()

	m := GetMonitor()
	m.Notify(func(info NetworkInfo) { emit(info) })
	if err := m.Start(); err != nil {
		return -1
	}
	monitorMu.Lock()
	monitor = m
	monitorMu.Unlock()
	return 0
}

//export stopNetworkMonitor
func stopNetworkMonitor() {
	monitorMu.Lock()
	defer monitorMu.Unlock()
	if monitor != nil {
		monitor.Stop()
		monitor = nil
	}
}

//export getNetworkInfoJson
func getNetworkInfoJson() *C.char {
	monitorMu.Lock()
	m := monitor
	monitorMu.Unlock()
	if m == nil {
		return C.CString(`{"type":"disconnected"}`)
	}
	return C.CString(infoJSON(m.Current()))
}
