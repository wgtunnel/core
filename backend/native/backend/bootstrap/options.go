package bootstrap

import (
	"net"
	"time"
)

// Options is the input for a one-shot bootstrap resolution
type Options struct {
	Protocol         string // doh, dot, plain
	ResolvedUpstream string // addresses / url that is already resolved
	OriginalUpstream string // original string SNI for DoT/DoH
	Dialer           *net.Dialer
	Timeout          time.Duration // default 5s if 0
}

func (o Options) withDefaults() Options {
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Dialer == nil {
		o.Dialer = &net.Dialer{}
	}
	return o
}
