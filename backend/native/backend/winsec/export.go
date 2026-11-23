// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build cgo && !android

package winsec

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/wgtunnel/backend/log"
)

// FileOwnerSid returns the owner SID of path, or NULL if it can't be read.
// The caller frees the result.
//
//export FileOwnerSid
func FileOwnerSid(path string) *C.char {
	sid, err := OwnerSID(path)
	if err != nil {
		log.Debug("WinSec", "owner sid: %v", err)
		return nil
	}
	return C.CString(sid)
}

// ProtectSecret DPAPI-encrypts base64 input for the calling account and returns base64,
// or NULL on failure. The caller frees the result.
//
//export ProtectSecret
func ProtectSecret(b64 string) *C.char {
	return transformB64(b64, Protect, "protect")
}

// UnprotectSecret reverses ProtectSecret, or returns NULL on failure. The caller frees the
// result.
//
//export UnprotectSecret
func UnprotectSecret(b64 string) *C.char {
	return transformB64(b64, Unprotect, "unprotect")
}

func transformB64(b64 string, fn func([]byte) ([]byte, error), op string) *C.char {
	in, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Error("WinSec", "%s: bad input: %v", op, err)
		return nil
	}
	out, err := fn(in)
	if err != nil {
		log.Error("WinSec", "%s: %v", op, err)
		return nil
	}
	return C.CString(base64.StdEncoding.EncodeToString(out))
}

// RunAsAdminWait starts path with args through a UAC prompt and waits for it. Returns the
// exit code, -2 when the user cancels the prompt, or -1 on any other failure.
//
//export RunAsAdminWait
func RunAsAdminWait(path, args string) C.int {
	code, err := RunAsAdmin(path, args, 2*time.Minute)
	switch {
	case errors.Is(err, ErrElevationCancelled):
		return -2
	case err != nil:
		log.Error("WinSec", "run as admin: %v", err)
		return -1
	}
	return C.int(code)
}
