package local

import (
	"context"
	"net/netip"
)

type Resolver interface {
	RawExchange(ctx context.Context, networkHandle int64, request []byte) ([]byte, error)
	Lookup(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error)
}

var ErrNotSupported = errNotSupported{}

type errNotSupported struct{}

func (errNotSupported) Error() string { return "dns/platform: not supported" }
