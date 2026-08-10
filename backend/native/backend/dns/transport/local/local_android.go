//go:build android

package local

import (
	"context"
	"net/netip"

	"github.com/wgtunnel/backend/dns/transport"
)

// NewLocalTransport is what tunwrap/setup receives on Android
func NewLocalTransport() transport.Transport {
	resolver := NewResolver(func(ctx context.Context, _ int64, network, host string) ([]netip.Addr, error) {
		return jniLookupOnUnderlayNetwork(ctx, network, host)
	})
	t := New(resolver)
	t.SetNetworkHandleFunc(CurrentUnderlayNetworkHandle)
	return t
}
