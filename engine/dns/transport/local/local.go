package local

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
	coredns "github.com/wgtunnel/core/engine/dns"
	"github.com/wgtunnel/core/engine/platform"
	"github.com/wgtunnel/core/log"
)

var (
	ErrNoUnderlayHandle = errors.New("local: no underlying network handle")
)

func IsNoHandleError(err error) bool {
	return errors.Is(err, ErrNoUnderlayHandle)
}

type Transport struct {
	mu         sync.RWMutex
	handleFunc func() int64
	resolver   platform.Resolver
	logger     *log.Logger
}

func New(resolver platform.Resolver) *Transport {
	return &Transport{
		resolver: resolver,
		logger:   log.Nop(),
	}
}

func (t *Transport) Type() string { return "local" }

func (t *Transport) SetLogger(l *log.Logger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l == nil {
		l = log.Nop()
	}
	t.logger = l
}

func (t *Transport) log() *log.Logger {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.logger != nil {
		return t.logger
	}
	return log.Nop()
}

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

func (t *Transport) SetResolver(r platform.Resolver) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resolver = r
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

	handle := t.currentHandle()
	if handle == 0 {
		t.log().Verbosef("local: no underlay handle for %s", name)
		return nil, fmt.Errorf("%w", ErrNoUnderlayHandle)
	}

	raw, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("local: pack: %w", err)
	}

	respBytes, err := resolver.RawExchange(ctx, handle, raw)
	if err == nil {
		resp := new(dns.Msg)
		if err := resp.Unpack(respBytes); err != nil {
			return nil, fmt.Errorf("local: unpack raw response: %w", err)
		}
		return resp, nil
	}

	if !errors.Is(err, platform.ErrNotSupported) {
		t.log().Errorf("local: raw exchange handle=%d name=%s: %v", handle, name, err)
		return nil, fmt.Errorf("local: raw exchange: %w", err)
	}

	t.log().Verbosef("local: raw unsupported, fallback lookup name=%s handle=%d", name, handle)
	return t.lookupFallback(ctx, resolver, handle, msg)
}

func (t *Transport) lookupFallback(
	ctx context.Context,
	resolver platform.Resolver,
	handle int64,
	msg *dns.Msg,
) (*dns.Msg, error) {
	if handle == 0 {
		return nil, fmt.Errorf("%w", ErrNoUnderlayHandle)
	}
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
		t.log().Errorf("local: fallback lookup name=%s family=%s: %v", name, network, err)
		return nil, fmt.Errorf("local: lookup: %w", err)
	}

	t.log().Verbosef("local: fallback ok name=%s family=%s addrs=%d", name, network, len(addrs))
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
	_ coredns.Transport      = (*Transport)(nil)
	_ coredns.LocalTransport = (*Transport)(nil)
)
