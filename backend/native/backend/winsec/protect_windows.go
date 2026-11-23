// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build windows

package winsec

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Protect encrypts data with DPAPI for the calling account. The daemon runs as SYSTEM,
// so only SYSTEM can decrypt it.
func Protect(data []byte) ([]byte, error) {
	in := blob(data)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

// Unprotect decrypts data from Protect.
func Unprotect(data []byte) ([]byte, error) {
	in := blob(data)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func blob(data []byte) windows.DataBlob {
	if len(data) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

func takeBlob(b *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return append([]byte(nil), unsafe.Slice(b.Data, b.Size)...)
}
