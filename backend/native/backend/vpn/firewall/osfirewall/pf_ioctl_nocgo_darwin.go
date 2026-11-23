// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build darwin && !cgo

package osfirewall

import "fmt"

func hasPFAnchor(name string) (bool, error) {
	return false, fmt.Errorf("read pf anchor %s: cgo is required", name)
}

func addPFAnchor(name string) error {
	return fmt.Errorf("insert pf anchor %s: cgo is required", name)
}

func removePFAnchor(name string) error {
	return fmt.Errorf("remove pf anchor %s: cgo is required", name)
}

func killBlockedPFStates(pfKeep) error {
	return fmt.Errorf("pf state kill: cgo is required")
}
