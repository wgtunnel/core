package transport

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// Transport is the common interface all DNS transports
type Transport interface {
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	Close() error
}

// PerAttemptContext bounds one candidate attempt to a fair share of whatever time remains on ctx,
// splitting evenly across remainingAttempts. Without this, transports that loop over multiple
// upstream addresses using the same shared ctx let a single slow/unreachable
// candidate consume the entire deadline, starving every later fallback
// candidate of any chance to be tried at all.
func PerAttemptContext(ctx context.Context, remainingAttempts int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || remainingAttempts <= 1 {
		return context.WithCancel(ctx)
	}
	share := time.Until(deadline) / time.Duration(remainingAttempts)
	if share <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, share)
}

// LocalTransport is an extended interface for transports that talk to
// the platform's underlying network resolver
type LocalTransport interface {
	Transport
	SetNetworkHandleFunc(fn func() int64)
}
