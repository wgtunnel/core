package local

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport"
	"github.com/wgtunnel/backend/log"
)

const tag = "LocalTransport"

var (
	ErrNoUnderlayHandle = errors.New("local: no underlying network handle")
)

func IsNoHandleError(err error) bool {
	return errors.Is(err, ErrNoUnderlayHandle)
}

type Transport struct {
	mu         sync.RWMutex
	handleFunc func() int64
	resolver   Resolver
}

func New(resolver Resolver) *Transport {
	return &Transport{
		resolver: resolver,
	}
}

func (t *Transport) Type() string { return "local" }

func (t *Transport) SetNetworkHandleFunc(fn func() int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handleFunc = fn
}

func (t *Transport) currentHandle() int64 {
	t.mu.RLock()
	fn := t.handleFunc
	t.mu.RUnlock()
	if fn == nil {
		return 0
	}
	return fn()
}

func (t *Transport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	t.mu.RLock()
	resolver := t.resolver
	t.mu.RUnlock()
	if resolver == nil {
		return nil, fmt.Errorf("local: no platform resolver configured")
	}

	name := ""
	if len(msg.Question) > 0 {
		name = msg.Question[0].Name
	}

	raw, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("local: pack: %w", err)
	}

	handle := t.currentHandle()

	respBytes, err := resolver.RawExchange(ctx, handle, raw)
	if err == nil {
		resp := new(dns.Msg)
		if err := resp.Unpack(respBytes); err != nil {
			return nil, fmt.Errorf("local: unpack: %w", err)
		}
		return resp, nil
	}

	if !errors.Is(err, ErrNotSupported) {
		log.Error(tag, "raw exchange handle=%d name=%s: %v", handle, name, err)
		return nil, fmt.Errorf("local: raw exchange: %w", err)
	}

	log.Debug(tag, "raw unsupported/empty, fallback lookup name=%s handle=%d", name, handle)
	return t.lookupFallback(ctx, resolver, handle, msg)
}

func (t *Transport) lookupFallback(
	ctx context.Context,
	resolver Resolver,
	handle int64,
	msg *dns.Msg,
) (*dns.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("local: empty question")
	}
	q := msg.Question[0]
	name := strings.TrimSuffix(q.Name, ".")

	var network string
	switch q.Qtype {
	case dns.TypeA:
		network = "ip4"
	case dns.TypeAAAA:
		network = "ip6"
	default:
		return nil, fmt.Errorf("local: lookup fallback only supports A/AAAA, got %d", q.Qtype)
	}

	addrs, err := resolver.Lookup(ctx, handle, network, name)
	if err != nil {
		return nil, fmt.Errorf("local: lookup: %w", err)
	}
	return buildResponse(msg, q, addrs), nil
}

func buildResponse(req *dns.Msg, q dns.Question, addrs []netip.Addr) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	for _, addr := range addrs {
		switch {
		case q.Qtype == dns.TypeA && addr.Is4():
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: addr.AsSlice(),
			})
		case q.Qtype == dns.TypeAAAA && addr.Is6():
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: addr.AsSlice(),
			})
		}
	}
	return resp
}

func (t *Transport) Close() error { return nil }

var (
	_ transport.Transport      = (*Transport)(nil)
	_ transport.LocalTransport = (*Transport)(nil)
)
