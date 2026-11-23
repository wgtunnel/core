// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build windows

package winsec

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// SHELLEXECUTEINFOW
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoConsole      = 0x00008000
)

// ErrElevationCancelled is returned when the user declines the UAC prompt.
var ErrElevationCancelled = errors.New("elevation cancelled")

// RunAsAdmin starts path with args through a UAC prompt and waits up to timeout for it to
// exit, returning its exit code.
func RunAsAdmin(path, args string, timeout time.Duration) (uint32, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoConsole,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if ok, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); ok == 0 {
		if errors.Is(callErr, windows.ERROR_CANCELLED) {
			return 0, ErrElevationCancelled
		}
		return 0, callErr
	}
	if info.hProcess == 0 {
		return 0, errors.New("no process handle")
	}
	defer windows.CloseHandle(info.hProcess)
	event, err := windows.WaitForSingleObject(info.hProcess, uint32(timeout.Milliseconds()))
	if err != nil {
		return 0, err
	}
	if event != windows.WAIT_OBJECT_0 {
		return 0, errors.New("timed out waiting for the elevated process")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return code, nil
}
