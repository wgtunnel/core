// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build !windows

package winsec

import (
	"errors"
	"time"
)

// ErrElevationCancelled is returned when the user declines the UAC prompt.
var ErrElevationCancelled = errors.New("elevation cancelled")

// RunAsAdmin is only implemented on Windows.
func RunAsAdmin(string, string, time.Duration) (uint32, error) { return 0, errors.ErrUnsupported }
