// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build !windows

package winsec

import "errors"

// OwnerSID is only implemented on Windows.
func OwnerSID(string) (string, error) {
	return "", errors.ErrUnsupported
}
