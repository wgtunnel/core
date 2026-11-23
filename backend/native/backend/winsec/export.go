// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build cgo && !android

package winsec

/*
#include <stdlib.h>
*/
import "C"

import "github.com/wgtunnel/backend/log"

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
