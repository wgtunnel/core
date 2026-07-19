//go:build !android

package desktop

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/wgtunnel/core/engine/platform"
)

// Resolver implements platform.Resolver for Desktop
// It uses a bypass dialer so DNS queries leave via the physical interface instead of being captured by the TUN
type Resolver struct {
	// Dialer should be a bypass dialer
	// If nil, a plain net.Dialer is used
	Dialer *net.Dialer

	// Servers is the list of upstream DNS servers used for both RawExchange and Lookup
	Servers []string

	// Timeout for each query
	Timeout time.Duration
}

// NewResolver creates a desktop resolver
func NewResolver(dialer *net.Dialer, servers []string) *Resolver {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &Resolver{
		Dialer:  dialer,
		Servers: servers,
		Timeout: 5 * time.Second,
	}
}

func (r *Resolver) RawExchange(ctx context.Context, networkHandle int64, request []byte) ([]byte, error) {
	// networkHandle is ignored on desktop (primary for Android)
	_ = networkHandle

	if len(request) == 0 {
		return nil, fmt.Errorf("desktop resolver: empty request")
	}

	client := &dns.Client{
		Net:     "udp",
		Dialer:  r.Dialer,
		Timeout: r.Timeout,
		UDPSize: 4096,
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(request); err != nil {
		return nil, fmt.Errorf("desktop resolver: unpack: %w", err)
	}

	var lastErr error
	for _, server := range r.Servers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("desktop resolver: nil response from %s", server)
			continue
		}
		out, err := resp.Pack()
		if err != nil {
			lastErr = err
			continue
		}
		return out, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("desktop resolver: all servers failed")
	}
	return nil, lastErr
}

func (r *Resolver) Lookup(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error) {
	// networkHandle is ignored on desktop
	_ = networkHandle

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Force the bypass dialer
			for _, server := range r.Servers {
				conn, err := r.Dialer.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
			}
			// Fallback, try the address the stdlib asked for
			return r.Dialer.DialContext(ctx, network, address)
		},
	}

	ips, err := resolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

var _ platform.Resolver = (*Resolver)(nil)
