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
	modCombase                    = windows.NewLazySystemDLL("combase.dll")
	procRoInitialize              = modCombase.NewProc("RoInitialize")
	procRoUninitialize            = modCombase.NewProc("RoUninitialize")
	procRoGetActivationFactory    = modCombase.NewProc("RoGetActivationFactory")
	procWindowsCreateString       = modCombase.NewProc("WindowsCreateString")
	procWindowsDeleteString       = modCombase.NewProc("WindowsDeleteString")
	procWindowsGetStringRawBuffer = modCombase.NewProc("WindowsGetStringRawBuffer")
)

const roInitMultithreaded = 1

var (
	iidINetworkInformationStatics = windows.GUID{
		Data1: 0x5074f851, Data2: 0x950d, Data3: 0x4165,
		Data4: [8]byte{0x9c, 0x15, 0x36, 0x56, 0x19, 0x48, 0x1e, 0xea},
	}
	iidIConnectionProfile = windows.GUID{
		Data1: 0x71ba143c, Data2: 0x598e, Data3: 0x49d0,
		Data4: [8]byte{0x84, 0xeb, 0x8f, 0xeb, 0xae, 0xdc, 0xc1, 0x95},
	}
	iidIConnectionProfile2 = windows.GUID{
		Data1: 0xe2045145, Data2: 0x4c9f, Data3: 0x400c,
		Data4: [8]byte{0x91, 0x50, 0x7e, 0xc7, 0xd6, 0xe2, 0x88, 0x8a},
	}
	iidIWlanConnectionProfileDetails = windows.GUID{
		Data1: 0x562098cb, Data2: 0xb35a, Data3: 0x4bf1,
		Data4: [8]byte{0xa8, 0x84, 0xb7, 0x55, 0x7e, 0x88, 0xff, 0x86},
	}
	iidINetworkAdapter = windows.GUID{
		Data1: 0x3b542e03, Data2: 0x5388, Data3: 0x496c,
		Data4: [8]byte{0xa8, 0xa3, 0xaf, 0xfd, 0x39, 0xae, 0xc2, 0xe6},
	}
)

// connectedSSIDWinRT returns the joined WLAN SSID for adapterGUID using
// WlanConnectionProfileDetails.GetConnectedSsid. This is not location-gated
// on Windows 11 24H2 (unlike WlanQueryInterface current_connection).
func connectedSSIDWinRT(adapterGUID windows.GUID) (string, error) {
	// COM/WinRT apartment membership is per-OS-thread; pin this goroutine so
	// RoInitialize below and every vtable call after it run on the same
	// thread. Without this, the Go scheduler can migrate mid-call and land
	// on a thread that never joined the apartment.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr, _, _ := procRoInitialize.Call(uintptr(roInitMultithreaded))
	if int32(hr) < 0 {
		return "", fmt.Errorf("RoInitialize: 0x%x", uint32(hr))
	}
	defer procRoUninitialize.Call()

	className, err := windowsCreateString("Windows.Networking.Connectivity.NetworkInformation")
	if err != nil {
		return "", err
	}
	defer windowsDeleteString(className)

	var factory uintptr
	hr, _, _ = procRoGetActivationFactory.Call(
		className,
		uintptr(unsafe.Pointer(&iidINetworkInformationStatics)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if int32(hr) < 0 || factory == 0 {
		return "", fmt.Errorf("RoGetActivationFactory: 0x%x", uint32(hr))
	}
	defer comRelease(factory)

	if ssid := ssidFromInternetProfile(factory, adapterGUID); ssid != "" {
		return ssid, nil
	}
	return ssidFromAllProfiles(factory, adapterGUID)
}

func ssidFromInternetProfile(factory uintptr, adapterGUID windows.GUID) string {
	vtbl := comVtbl(factory)
	var profile uintptr
	hr, _, _ := syscall.SyscallN(vtbl[7], factory, uintptr(unsafe.Pointer(&profile))) // GetInternetConnectionProfile
	if int32(hr) < 0 || profile == 0 {
		return ""
	}
	defer comRelease(profile)
	return ssidFromConnectionProfile(profile, adapterGUID)
}

func ssidFromAllProfiles(factory uintptr, adapterGUID windows.GUID) (string, error) {
	vtbl := comVtbl(factory)
	var view uintptr
	hr, _, _ := syscall.SyscallN(vtbl[6], factory, uintptr(unsafe.Pointer(&view))) // GetConnectionProfiles
	if int32(hr) < 0 || view == 0 {
		return "", fmt.Errorf("GetConnectionProfiles: 0x%x", uint32(hr))
	}
	defer comRelease(view)

	// IVectorView<T> : IInspectable(6); GetAt=6, get_Size=7, IndexOf=8, GetMany=9.
	viewVtbl := comVtbl(view)
	var n uint32
	hr, _, _ = syscall.SyscallN(viewVtbl[7], view, uintptr(unsafe.Pointer(&n))) // get_Size
	if int32(hr) < 0 {
		return "", fmt.Errorf("IVectorView.get_Size: 0x%x", uint32(hr))
	}
	for i := uint32(0); i < n; i++ {
		var profile uintptr
		hr, _, _ = syscall.SyscallN(viewVtbl[6], view, uintptr(i), uintptr(unsafe.Pointer(&profile))) // GetAt
		if int32(hr) < 0 || profile == 0 {
			continue
		}
		ssid := ssidFromConnectionProfile(profile, adapterGUID)
		comRelease(profile)
		if ssid != "" {
			return ssid, nil
		}
	}
	return "", nil
}

func ssidFromConnectionProfile(profile uintptr, adapterGUID windows.GUID) string {
	p2, err := comQuery(profile, &iidIConnectionProfile2)
	if err != nil {
		return ""
	}
	defer comRelease(p2)
	p2Vtbl := comVtbl(p2)

	var isWlan uint8
	hr, _, _ := syscall.SyscallN(p2Vtbl[7], p2, uintptr(unsafe.Pointer(&isWlan))) // get_IsWlanConnectionProfile
	if int32(hr) < 0 || isWlan == 0 {
		return ""
	}

	if adapterGUID != (windows.GUID{}) {
		cp, err := comQuery(profile, &iidIConnectionProfile)
		if err != nil {
			return ""
		}
		defer comRelease(cp)
		cpVtbl := comVtbl(cp)
		var adapter uintptr
		hr, _, _ = syscall.SyscallN(cpVtbl[11], cp, uintptr(unsafe.Pointer(&adapter))) // get_NetworkAdapter
		if int32(hr) < 0 || adapter == 0 {
			return ""
		}
		defer comRelease(adapter)
		na, err := comQuery(adapter, &iidINetworkAdapter)
		if err != nil {
			return ""
		}
		defer comRelease(na)
		naVtbl := comVtbl(na)
		var id windows.GUID
		hr, _, _ = syscall.SyscallN(naVtbl[10], na, uintptr(unsafe.Pointer(&id))) // get_NetworkAdapterId
		if int32(hr) < 0 || id != adapterGUID {
			return ""
		}
	}

	var details uintptr
	hr, _, _ = syscall.SyscallN(p2Vtbl[9], p2, uintptr(unsafe.Pointer(&details))) // get_WlanConnectionProfileDetails
	if int32(hr) < 0 || details == 0 {
		return ""
	}
	defer comRelease(details)
	wlan, err := comQuery(details, &iidIWlanConnectionProfileDetails)
	if err != nil {
		return ""
	}
	defer comRelease(wlan)
	wlanVtbl := comVtbl(wlan)
	var hstr uintptr
	hr, _, _ = syscall.SyscallN(wlanVtbl[6], wlan, uintptr(unsafe.Pointer(&hstr))) // GetConnectedSsid
	if int32(hr) < 0 || hstr == 0 {
		return ""
	}
	defer windowsDeleteString(hstr)
	return hstringToString(hstr)
}

func windowsCreateString(s string) (uintptr, error) {
	u16, err := windows.UTF16FromString(s)
	if err != nil {
		return 0, err
	}
	n := uint32(len(u16))
	if n > 0 {
		n-- // exclude NUL
	}
	var hstr uintptr
	hr, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(n),
		uintptr(unsafe.Pointer(&hstr)),
	)
	if int32(hr) < 0 {
		return 0, fmt.Errorf("WindowsCreateString: 0x%x", uint32(hr))
	}
	return hstr, nil
}

func windowsDeleteString(hstr uintptr) {
	if hstr != 0 {
		procWindowsDeleteString.Call(hstr)
	}
}

func hstringToString(hstr uintptr) string {
	if hstr == 0 {
		return ""
	}
	var n uint32
	p, _, _ := procWindowsGetStringRawBuffer.Call(hstr, uintptr(unsafe.Pointer(&n)))
	if p == 0 || n == 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(p)), n))
}

func comVtbl(punk uintptr) *[16]uintptr {
	return *(**[16]uintptr)(unsafe.Pointer(punk))
}

func comRelease(punk uintptr) {
	if punk == 0 {
		return
	}
	syscall.SyscallN(comVtbl(punk)[2], punk)
}

func comQuery(punk uintptr, iid *windows.GUID) (uintptr, error) {
	var out uintptr
	hr, _, _ := syscall.SyscallN(comVtbl(punk)[0], punk, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == 0 {
		return 0, fmt.Errorf("QueryInterface: 0x%x", uint32(hr))
	}
	return out, nil
}
