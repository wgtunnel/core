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
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
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

type wifiDetails struct {
	SSID, BSSID    string
	Wireless       bool
	Associated     bool
	LocationDenied bool
}

// wifiInfoForInterface returns SSID/BSSID for the TCP/IP adapter identified
// by LUID / InterfaceGUID.
func wifiInfoForInterface(luid winipcfg.LUID, ifaceGUID windows.GUID, description string) (wifiDetails, error) {
	var d wifiDetails
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
			return d, fmt.Errorf("WlanOpenHandle: %v", e)
		}
		return d, fmt.Errorf("WlanOpenHandle: %d", r)
	}
	defer procWlanCloseHandle.Call(handle, 0)

	var listPtr uintptr
	r, _, e = procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if r != 0 || listPtr == 0 {
		if !errors.Is(e, syscall.Errno(0)) {
			return d, fmt.Errorf("WlanEnumInterfaces: %v", e)
		}
		return d, fmt.Errorf("WlanEnumInterfaces: %d", r)
	}
	defer procWlanFreeMemory.Call(listPtr)

	list := (*wlanInterfaceList)(unsafe.Pointer(listPtr))
	n := int(list.dwNumberOfItems)
	if n <= 0 {
		return d, nil
	}
	infos := unsafe.Slice(&list.InterfaceInfo[0], n)

	matched := matchWlanInterface(infos, luid, ifaceGUID, description)
	if matched == nil {
		seen := make([]string, 0, n)
		for i := range infos {
			seen = append(seen, infos[i].InterfaceGUID.String())
		}
		return d, fmt.Errorf(
			"no WLAN interface matched GUID %s desc=%q (enumerated: %v)",
			ifaceGUID.String(), description, seen,
		)
	}

	d.Wireless = true
	if matched.isState != wlanInterfaceStateConnected {
		return d, nil
	}
	d.Associated = true

	ssid, bssid, denied, qerr := queryCurrentConnection(handle, &matched.InterfaceGUID)
	if denied {
		d.LocationDenied = true
		return d, qerr
	}
	if qerr != nil {
		return d, nil
	}
	d.SSID = ssid
	d.BSSID = bssid
	return d, nil
}

func queryCurrentConnection(handle uintptr, guid *windows.GUID) (ssid, bssid string, locationDenied bool, err error) {
	var dataPtr uintptr
	var dataSize uint32
	var opcodeCode uint32
	r, _, e := procWlanQueryInterface.Call(
		handle,
		uintptr(unsafe.Pointer(guid)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		uintptr(unsafe.Pointer(&opcodeCode)),
	)
	if r == uintptr(windows.ERROR_ACCESS_DENIED) {
		return "", "", true, fmt.Errorf("WlanQueryInterface: access denied")
	}
	if r != 0 || dataPtr == 0 {
		if !errors.Is(e, syscall.Errno(0)) && r != 0 {
			return "", "", false, fmt.Errorf("WlanQueryInterface: %v", e)
		}
		return "", "", false, fmt.Errorf("WlanQueryInterface: %d", r)
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
	if ssid == "" {
		ssid = windows.UTF16ToString(attrs.strProfileName[:])
	}
	b := attrs.wlanAssociationAttributes.dot11Bssid
	if b != [6]byte{} {
		bssid = net.HardwareAddr(b[:]).String()
	}
	return ssid, bssid, false, nil
}

// wifiSSIDLocationDenied reports whether Windows 11 24H2+ is blocking
// WlanQueryInterface(current_connection) without precise-location consent.
func wifiSSIDLocationDenied() bool {
	var handle uintptr
	var negotiated uint32
	r, _, _ := procWlanOpenHandle.Call(
		uintptr(wlanClientVersionVista),
		0,
		uintptr(unsafe.Pointer(&negotiated)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if r != 0 {
		return false
	}
	defer procWlanCloseHandle.Call(handle, 0)

	var listPtr uintptr
	r, _, _ = procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if r != 0 || listPtr == 0 {
		return false
	}
	defer procWlanFreeMemory.Call(listPtr)

	list := (*wlanInterfaceList)(unsafe.Pointer(listPtr))
	n := int(list.dwNumberOfItems)
	if n <= 0 {
		return false
	}
	infos := unsafe.Slice(&list.InterfaceInfo[0], n)
	// Location consent is process-wide, but a disconnected radio often
	// returns ERROR_INVALID_STATE instead of ACCESS_DENIED. Query each
	// iface until one reports the location gate.
	for i := range infos {
		_, _, denied, _ := queryCurrentConnection(handle, &infos[i].InterfaceGUID)
		if denied {
			return true
		}
	}
	return false
}

func matchWlanInterface(infos []wlanInterfaceInfo, luid winipcfg.LUID, ifaceGUID windows.GUID, description string) *wlanInterfaceInfo {
	if ifaceGUID != (windows.GUID{}) {
		for i := range infos {
			if infos[i].InterfaceGUID == ifaceGUID {
				return &infos[i]
			}
		}
	}

	if luid != 0 {
		for i := range infos {
			wlanLUID, err := winipcfg.LUIDFromGUID(&infos[i].InterfaceGUID)
			if err == nil && wlanLUID == luid {
				return &infos[i]
			}
		}
	}

	wantDesc := strings.ToLower(strings.TrimSpace(description))
	if wantDesc != "" {
		for i := range infos {
			got := strings.ToLower(strings.TrimSpace(
				windows.UTF16ToString(infos[i].strInterfaceDescription[:]),
			))
			if got == wantDesc {
				return &infos[i]
			}
		}
	}

	// Single-radio machines: Chromium notes most cards expose one managed
	// WLAN interface. Use it only when GUID/LUID/description all missed.
	if len(infos) == 1 {
		return &infos[0]
	}
	return nil
}
