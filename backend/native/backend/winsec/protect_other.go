// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build !windows

package winsec

import "errors"

// Protect is only implemented on Windows.
func Protect([]byte) ([]byte, error) { return nil, errors.ErrUnsupported }

// Unprotect is only implemented on Windows.
func Unprotect([]byte) ([]byte, error) { return nil, errors.ErrUnsupported }
