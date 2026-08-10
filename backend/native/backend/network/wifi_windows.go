//go:build windows

package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWlanapi = windows.NewLazySystemDLL("wlanapi.dll")

	procWlanOpenHandle     = modWlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

const (
	wlanClientVersionVista          = 2
	wlanIntfOpcodeCurrentConnection = 7
	wlanInterfaceStateConnected     = 1
)

type wlanInterfaceInfo struct {
	InterfaceGUID           windows.GUID
	strInterfaceDescription [256]uint16
	isState                 uint32
	// rest ignored
}

type wlanInterfaceList struct {
	dwNumberOfItems uint32
	dwIndex         uint32
	InterfaceInfo   [1]wlanInterfaceInfo
}

type dot11SSID struct {
	uSSIDLength uint32
	ucSSID      [32]byte
}

type wlanAssociationAttributes struct {
	dot11Ssid         dot11SSID
	dot11BssType      uint32
	dot11Bssid        [6]byte
	dot11PhyType      uint32
	uDot11PhyIndex    uint32
	wlanSignalQuality uint32
	ulRxRate          uint32
	ulTxRate          uint32
}

type wlanConnectionAttributes struct {
	isState                   uint32
	wlanConnectionMode        uint32
	strProfileName            [256]uint16
	wlanAssociationAttributes wlanAssociationAttributes
	// security attrs follow — not needed
}

// wifiInfoForInterface returns ssid, bssid, wireless.
// wireless is true if this ifIndex is a WLAN interface.
func wifiInfoForInterface(ifIndex uint32, ifName string) (ssid, bssid string, wireless bool, err error) {
	var handle uintptr
	var negotiated uint32
	r, _, e := procWlanOpenHandle.Call(
		uintptr(wlanClientVersionVista),
		0,
		uintptr(unsafe.Pointer(&negotiated)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if r != 0 {
		if !errors.Is(e, syscall.Errno(0)) {
			return "", "", false, fmt.Errorf("WlanOpenHandle: %v", e)
		}
		return "", "", false, fmt.Errorf("WlanOpenHandle: %d", r)
	}
	defer procWlanCloseHandle.Call(handle, 0)

	var listPtr uintptr
	r, _, e = procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if r != 0 || listPtr == 0 {
		if !errors.Is(e, syscall.Errno(0)) {
			return "", "", false, fmt.Errorf("WlanEnumInterfaces: %v", e)
		}
		return "", "", false, fmt.Errorf("WlanEnumInterfaces: %d", r)
	}
	defer procWlanFreeMemory.Call(listPtr)

	list := (*wlanInterfaceList)(unsafe.Pointer(listPtr))
	n := int(list.dwNumberOfItems)
	infos := unsafe.Slice(&list.InterfaceInfo[0], n)

	// Match WLAN interface by description to friendly name
	targetName := stringsEqualFoldNormalize(ifName)

	var matched *wlanInterfaceInfo
	for i := range infos {
		desc := windows.UTF16ToString(infos[i].strInterfaceDescription[:])
		if targetName != "" && stringsEqualFoldNormalize(desc) == targetName {
			matched = &infos[i]
			break
		}
	}

	if matched == nil {
		return "", "", false, nil // not wireless
	}

	wireless = true
	if matched.isState != wlanInterfaceStateConnected {
		return "", "", true, nil // Wi-Fi iface, not associated
	}

	var dataPtr uintptr
	var dataSize uint32
	var opcodeCode uint32
	r, _, e = procWlanQueryInterface.Call(
		handle,
		uintptr(unsafe.Pointer(&matched.InterfaceGUID)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		uintptr(unsafe.Pointer(&opcodeCode)),
	)
	if r != 0 || dataPtr == 0 {
		return "", "", true, nil // connected state but query failed
	}
	defer procWlanFreeMemory.Call(dataPtr)

	attrs := (*wlanConnectionAttributes)(unsafe.Pointer(dataPtr))
	ssidLen := int(attrs.wlanAssociationAttributes.dot11Ssid.uSSIDLength)
	if ssidLen > 32 {
		ssidLen = 32
	}
	if ssidLen > 0 {
		ssid = string(attrs.wlanAssociationAttributes.dot11Ssid.ucSSID[:ssidLen])
	}
	b := attrs.wlanAssociationAttributes.dot11Bssid
	if b != [6]byte{} {
		bssid = net.HardwareAddr(b[:]).String()
	}
	return ssid, bssid, true, nil
}

func stringsEqualFoldNormalize(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}
