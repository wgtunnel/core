package dns

import (
	"context"

	"github.com/miekg/dns"
)

// Transport is implemented by every DNS backend
type Transport interface {
	Type() string
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	Close() error
}

// LocalTransport is used for platform bypassed DNS
type LocalTransport interface {
	Transport
	// SetNetworkHandleFunc supplies a function that returns the current underlying network handle or Android or 0 if unknown
	SetNetworkHandleFunc(fn func() int64)
}
