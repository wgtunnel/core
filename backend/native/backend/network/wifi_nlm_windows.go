//go:build windows

package network

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modOle32             = windows.NewLazySystemDLL("ole32.dll")
	modOleaut32          = windows.NewLazySystemDLL("oleaut32.dll")
	procCoCreateInstance = modOle32.NewProc("CoCreateInstance")
	procSysFreeString    = modOleaut32.NewProc("SysFreeString")
)

const (
	clsctxInprocServer = 1
)

var (
	clsidNetworkListManager = windows.GUID{
		Data1: 0xdcb00c01, Data2: 0x570f, Data3: 0x4a9b,
		Data4: [8]byte{0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b},
	}
	iidINetworkListManager = windows.GUID{
		Data1: 0xdcb00000, Data2: 0x570f, Data3: 0x4a9b,
		Data4: [8]byte{0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b},
	}
)

// connectedSSIDNLM returns the connected network name for adapterGUID via
// the Network List Manager. For Wi-Fi this is typically the SSID. Not in
// Microsoft's 24H2 location-gated API list.
func connectedSSIDNLM(adapterGUID windows.GUID) (string, error) {
	// COM apartment membership is per-OS-thread; pin this goroutine so the
	// CoInitializeEx below and every vtable call after it run on the same
	// thread. Without this, the Go scheduler can migrate mid-call and land
	// on a thread that never joined the apartment.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	if hr == nil {
		defer windows.CoUninitialize()
	}

	var nlm uintptr
	r, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidNetworkListManager)),
		0,
		uintptr(clsctxInprocServer),
		uintptr(unsafe.Pointer(&iidINetworkListManager)),
		uintptr(unsafe.Pointer(&nlm)),
	)
	if int32(r) < 0 || nlm == 0 {
		return "", fmt.Errorf("CoCreateInstance(NLM): 0x%x", uint32(r))
	}
	defer comRelease(nlm)

	nlmVtbl := comVtbl(nlm)
	var enum uintptr
	// IUnknown(3)+IDispatch(4) => GetNetworkConnections is slot 9
	hrCall, _, _ := syscall.SyscallN(nlmVtbl[9], nlm, uintptr(unsafe.Pointer(&enum)))
	if int32(hrCall) < 0 || enum == 0 {
		return "", fmt.Errorf("GetNetworkConnections: 0x%x", uint32(hrCall))
	}
	defer comRelease(enum)

	enumVtbl := comVtbl(enum)
	for {
		var conn uintptr
		var fetched uint32
		// IEnumNetworkConnections : IDispatch(7) + get__NewEnum(7) => Next is slot 8.
		hrCall, _, _ = syscall.SyscallN(enumVtbl[8], enum, 1, uintptr(unsafe.Pointer(&conn)), uintptr(unsafe.Pointer(&fetched)))
		if fetched == 0 || conn == 0 {
			break
		}
		ssid := nlmSSIDFromConnection(conn, adapterGUID)
		comRelease(conn)
		if ssid != "" {
			return ssid, nil
		}
	}
	return "", nil
}

func nlmSSIDFromConnection(conn uintptr, adapterGUID windows.GUID) string {
	connVtbl := comVtbl(conn)
	var id windows.GUID
	// INetworkConnection : IDispatch(7); GetNetwork=7, get_IsConnectedToInternet=8,
	// get_IsConnected=9, GetConnectivity=10, GetConnectionId=11 => GetAdapterId=12.
	hr, _, _ := syscall.SyscallN(connVtbl[12], conn, uintptr(unsafe.Pointer(&id)))
	if int32(hr) < 0 {
		return ""
	}
	if adapterGUID != (windows.GUID{}) && id != adapterGUID {
		return ""
	}
	var net uintptr
	hr, _, _ = syscall.SyscallN(connVtbl[7], conn, uintptr(unsafe.Pointer(&net))) // GetNetwork
	if int32(hr) < 0 || net == 0 {
		return ""
	}
	defer comRelease(net)
	netVtbl := comVtbl(net)
	var bstr *uint16
	hr, _, _ = syscall.SyscallN(netVtbl[7], net, uintptr(unsafe.Pointer(&bstr))) // GetName
	if int32(hr) < 0 || bstr == nil {
		return ""
	}
	defer procSysFreeString.Call(uintptr(unsafe.Pointer(bstr)))
	return windows.UTF16PtrToString(bstr)
}
