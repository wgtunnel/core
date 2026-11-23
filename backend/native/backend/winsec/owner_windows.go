// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build windows

package winsec

import (
	"strings"

	"golang.org/x/sys/windows"
)

// OwnerSID returns the string SID of the account or group that owns path.
func OwnerSID(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		strings.Clone(path),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	return owner.String(), nil
}
