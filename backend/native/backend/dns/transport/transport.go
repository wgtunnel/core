package transport

import (
	"context"

	"github.com/miekg/dns"
)

// Transport is the common interface all DNS transports
type Transport interface {
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	Close() error
}

// LocalTransport is an extended interface for transports that talk to
// the platform's underlying network resolver
type LocalTransport interface {
	Transport
	SetNetworkHandleFunc(fn func() int64)
}
