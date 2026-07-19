package platform

import (
	"context"
	"net/netip"
)

// Network provides platform-specific capabilities
type Network interface {
	// NetworkHandle returns a platform handle used for binding, networkHandle for Android and interface index or 0 for desktop
	NetworkHandle() int64

	// Protect marks a file descriptor so it bypasses the VPN, protect on Android and SO_MARK or interface binding on desktop
	Protect(fd int) error
}

// Resolver is the platform-specific DNS backend used by the local transport
type Resolver interface {
	// RawExchange sends a full DNS packet on the given network handle and returns the raw response bytes
	RawExchange(ctx context.Context, networkHandle int64, request []byte) (response []byte, err error)

	// Lookup performs a high-level lookup via fallback path
	Lookup(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error)
}

// ErrNotSupported is returned by platform methods that are unavailable
var ErrNotSupported = errNotSupported{}

type errNotSupported struct{}

func (errNotSupported) Error() string { return "platform: not supported" }
