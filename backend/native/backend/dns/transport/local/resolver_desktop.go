//go:build !android

package local

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

type desktopResolver struct {
	underlay *UnderlayDNS
	dialer   *net.Dialer
	timeout  time.Duration
}

func NewResolver(underlay *UnderlayDNS, dialer *net.Dialer) Resolver {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &desktopResolver{underlay: underlay, dialer: dialer, timeout: 5 * time.Second}
}

// SetDialer To update the dialer when the physical interface changes
func (r *desktopResolver) SetDialer(d *net.Dialer) {
	if d != nil {
		r.dialer = d
	}
}

func (r *desktopResolver) RawExchange(ctx context.Context, _ int64, request []byte) ([]byte, error) {
	servers := r.underlay.Servers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("desktop local: no underlay DNS servers")
	}
	if len(request) == 0 {
		return nil, fmt.Errorf("desktop local: empty request")
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(request); err != nil {
		return nil, fmt.Errorf("desktop local: unpack: %w", err)
	}

	client := &dns.Client{
		Net:     "udp",
		Dialer:  r.dialer,
		Timeout: r.timeout,
		UDPSize: 4096,
	}

	var lastErr error
	for _, server := range servers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("nil response from %s", server)
			continue
		}
		return resp.Pack()
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all underlay DNS servers failed")
	}
	return nil, lastErr
}

func (r *desktopResolver) Lookup(ctx context.Context, _ int64, network, host string) ([]netip.Addr, error) {
	servers := r.underlay.Servers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("desktop local: no underlay DNS servers")
	}

	// Use miekg/dns directly against the underlay servers with the bypass dialer.
	client := &dns.Client{
		Net:     "udp",
		Dialer:  r.dialer,
		Timeout: r.timeout,
		UDPSize: 4096,
	}

	var qtype uint16
	switch network {
	case "ip4":
		qtype = dns.TypeA
	case "ip6":
		qtype = dns.TypeAAAA
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.SetEdns0(4096, true)

	var lastErr error
	for _, server := range servers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}
		var addrs []netip.Addr
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				if a, err := netip.ParseAddr(rr.A.String()); err == nil {
					addrs = append(addrs, a)
				}
			case *dns.AAAA:
				if a, err := netip.ParseAddr(rr.AAAA.String()); err == nil {
					addrs = append(addrs, a)
				}
			}
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no addresses for %s", host)
}

var _ Resolver = (*desktopResolver)(nil)
