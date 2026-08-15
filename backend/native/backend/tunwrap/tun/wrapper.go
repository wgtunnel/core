package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport/local"
	"github.com/wgtunnel/backend/log"
	tunDns "github.com/wgtunnel/backend/tunwrap/dns"
	"golang.org/x/sync/singleflight"
)

const (
	maxInFlightDNS   = 32
	maxCacheEntries  = 512
	dnsQueryTimeout  = 5 * time.Second
	negativeCacheTTL = 10 * time.Second // used for SERVFAIL and NXDOMAIN responses
	tag              = "WrapperTun"
)

type cacheEntry struct {
	msg    *dns.Msg
	expiry time.Time
}

// WrapperTUN wraps a tun.Device for intercepts
type WrapperTUN struct {
	realTUN          awgtun.Device
	dns              *tunDns.Engine
	fakeDNSv4        netip.Addr
	fakeDNSv6        netip.Addr
	foreignDNSPolicy string
	passthroughDNS   map[netip.Addr]struct{}

	dnsSem chan struct{}

	cacheMu sync.Mutex
	cache   map[string]cacheEntry

	mu     sync.Mutex
	closed bool
	group  singleflight.Group
}

func NewWrapperTUN(
	real awgtun.Device,
	dnsEngine *tunDns.Engine,
	fakeDNSv4 string,
	fakeDNSv6 string,
	foreignDnsPolicy string,
	passthrough []netip.Addr,
) (*WrapperTUN, error) {
	if dnsEngine == nil {
		return nil, fmt.Errorf("filtering tun: dns engine is nil")
	}
	v4, err := netip.ParseAddr(fakeDNSv4)
	if err != nil || !v4.Is4() {
		return nil, fmt.Errorf("filtering tun: invalid fake DNS v4 %q", fakeDNSv4)
	}
	var v6 netip.Addr
	if s := strings.TrimSpace(fakeDNSv6); s != "" {
		v6, err = netip.ParseAddr(s)
		if err != nil || !v6.Is6() {
			return nil, fmt.Errorf("filtering tun: invalid fake DNS v6 %q", fakeDNSv6)
		}
	}
	pass := make(map[netip.Addr]struct{}, len(passthrough))
	for _, a := range passthrough {
		if a.IsValid() {
			pass[a] = struct{}{}
		}
	}
	return &WrapperTUN{
		realTUN:          real,
		dns:              dnsEngine,
		fakeDNSv4:        v4,
		fakeDNSv6:        v6, // zero Addr if unused — IsValid() == false
		foreignDNSPolicy: foreignDnsPolicy,
		passthroughDNS:   pass,
		dnsSem:           make(chan struct{}, maxInFlightDNS),
		cache:            make(map[string]cacheEntry),
	}, nil
}

func (f *WrapperTUN) File() *os.File              { return f.realTUN.File() }
func (f *WrapperTUN) MTU() (int, error)           { return f.realTUN.MTU() }
func (f *WrapperTUN) Name() (string, error)       { return f.realTUN.Name() }
func (f *WrapperTUN) Events() <-chan awgtun.Event { return f.realTUN.Events() }
func (f *WrapperTUN) BatchSize() int              { return f.realTUN.BatchSize() }

func (f *WrapperTUN) Write(bufs [][]byte, offset int) (int, error) {
	return f.realTUN.Write(bufs, offset)
}

func (f *WrapperTUN) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.realTUN.Close()
}

func (f *WrapperTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := f.realTUN.Read(bufs, sizes, offset)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}

		out := 0
		for i := range n {
			pkt := bufs[i][offset : offset+sizes[i]]
			if f.handleDNSIfNeeded(pkt) {
				continue
			}
			if out != i {
				copy(bufs[out][offset:], pkt)
				sizes[out] = sizes[i]
			}
			out++
		}
		if out > 0 {
			return out, nil
		}
	}
}

func (f *WrapperTUN) handleDNSIfNeeded(packet []byte) bool {
	p, err := parseIPPacket(packet)
	if err != nil {
		return false
	}

	// TCP/53 is plain DNS-over-TCP, only allow if it is a system-tunnel FakeDNS upstream.
	if p.Protocol == 6 && p.DstPort == 53 {
		if _, ok := f.passthroughDNS[p.DstIP]; ok {
			return false
		}
		if f.foreignDNSPolicy == "allow" {
			return false
		}
		log.Debug(tag, "dns: drop tcp/53 %s to %s", p.SrcIP, p.DstIP)
		return true
	}

	if p.Protocol != 17 || p.DstPort != 53 {
		return false
	}

	if _, ok := f.passthroughDNS[p.DstIP]; ok {
		return false
	}

	toFake := isDNSQueryToFake(p, f.fakeDNSv4, f.fakeDNSv6)
	switch f.foreignDNSPolicy {
	case "allow":
		if !toFake {
			return false
		}
	case "drop":
		if !toFake {
			log.Debug(tag, "dns: drop udp/53 %s → %s", p.SrcIP, p.DstIP)
			return true
		}
	default: // "redirect" or empty
	}

	if len(p.Payload) == 0 {
		log.Debug(tag, "dns: empty udp payload, drop")
		return true
	}

	select {
	case f.dnsSem <- struct{}{}:
	default:
		log.Debug(tag, "dns: drop under load")
		return true
	}

	payload := make([]byte, len(p.Payload))
	copy(payload, p.Payload)
	orig := *p
	orig.Payload = payload

	go func() {
		defer func() { <-f.dnsSem }()
		defer func() {
			if rec := recover(); rec != nil {
				log.Error(tag, "dns: panic in resolveAndReply: %v", rec)
			}
		}()
		f.resolveAndReply(&orig)
	}()
	return true
}

func cacheKey(q dns.Question) string {
	return fmt.Sprintf("%s|%d", q.Name, q.Qtype)
}

func (f *WrapperTUN) cacheGet(q dns.Question) *dns.Msg {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()

	e, ok := f.cache[cacheKey(q)]
	if !ok {
		return nil
	}
	if time.Now().After(e.expiry) {
		delete(f.cache, cacheKey(q))
		return nil
	}
	return e.msg.Copy()
}

func (f *WrapperTUN) cachePut(q dns.Question, msg *dns.Msg, ttl time.Duration) {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()

	now := time.Now()
	key := cacheKey(q)

	if _, exists := f.cache[key]; !exists && len(f.cache) >= maxCacheEntries {
		// drop cache entries that have expired
		for k, e := range f.cache {
			if now.After(e.expiry) {
				delete(f.cache, k)
			}
		}
		// on limit reached, drop nearest to expiry
		for len(f.cache) >= maxCacheEntries {
			var victim string
			var soonest time.Time
			first := true
			for k, e := range f.cache {
				if first || e.expiry.Before(soonest) {
					victim, soonest, first = k, e.expiry, false
				}
			}
			if victim == "" {
				break
			}
			delete(f.cache, victim)
		}
	}

	f.cache[key] = cacheEntry{msg: msg.Copy(), expiry: now.Add(ttl)}
}

// Returns 0 if caller should not cache
func minAnswerTTL(msg *dns.Msg) time.Duration {
	var ttl time.Duration
	found := false
	for _, rr := range msg.Answer {
		if rr.Header().Ttl == 0 {
			continue
		}
		t := time.Duration(rr.Header().Ttl) * time.Second
		if !found || t < ttl {
			ttl = t
			found = true
		}
	}
	if !found {
		return 0
	}
	const maxCacheTTL = 5 * time.Minute // cap for mobile / network changes
	if ttl > maxCacheTTL {
		return maxCacheTTL
	}
	return ttl
}

func (f *WrapperTUN) resolveAndReply(orig *parsedPacket) {
	f.mu.Lock()
	closed := f.closed
	engine := f.dns
	f.mu.Unlock()
	if closed || engine == nil {
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(orig.Payload); err != nil {
		log.Error(tag, "dns: unpack: %v", err)
		return
	}
	if len(msg.Question) == 0 {
		return
	}

	q := msg.Question[0]
	key := cacheKey(q)

	// Check cache first for fast path
	if cached := f.cacheGet(q); cached != nil {
		cached.Id = msg.Id
		f.writeDNSResponse(orig, cached, q.Name)
		return
	}

	// Single flight protected resolution
	v, err, _ := f.group.Do(key, func() (any, error) {
		if cached := f.cacheGet(q); cached != nil {
			return cached, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
		defer cancel()

		result, err := engine.Exchange(ctx, msg)
		if err != nil {
			fail := new(dns.Msg)
			fail.SetRcode(msg, dns.RcodeServerFailure)

			ttl := negativeCacheTTL
			if local.IsNoHandleError(err) {
				log.Debug(tag, "local: no handle, returning SERVFAIL for %s", q.Name)
				ttl = 30 * time.Second // give more breathing room when handle is missing
			} else {
				log.Error(tag, "dns: exchange %s: %v", q.Name, err)
			}

			f.cachePut(q, fail, ttl)
			return fail, nil
		}

		if !result.DisableCache {
			if ttl := minAnswerTTL(result.Msg); ttl > 0 {
				f.cachePut(q, result.Msg, ttl)
			}
		}
		return result.Msg, nil
	})

	if err != nil {
		log.Error(tag, "dns: unexpected singleflight error for %s: %v", q.Name, err)
		fail := new(dns.Msg)
		fail.SetRcode(msg, dns.RcodeServerFailure)
		f.writeDNSResponse(orig, fail, q.Name)
		return
	}

	resp := v.(*dns.Msg).Copy()
	resp.Id = msg.Id
	f.writeDNSResponse(orig, resp, q.Name)
}

func (f *WrapperTUN) writeDNSResponse(orig *parsedPacket, resp *dns.Msg, name string) {
	respBytes, err := resp.Pack()
	if err != nil {
		log.Error(tag, "dns: pack %s: %v", name, err)
		return
	}

	mtu, err := f.realTUN.MTU()
	if err != nil || mtu <= 0 {
		mtu = 1280
	}

	outPacket, err := buildDNSResponse(orig, respBytes, mtu)
	if err != nil {
		log.Error(tag, "dns: build %s: %v", name, err)
		return
	}

	switch orig.IPVersion {
	case 4:
		if len(outPacket) < 20 {
			log.Error(tag, "dns: short v4 packet %s len=%d", name, len(outPacket))
			return
		}
		claimed := int(binary.BigEndian.Uint16(outPacket[2:4]))
		if claimed != len(outPacket) {
			log.Error(tag, "dns: v4 len mismatch %s claimed=%d actual=%d",
				name, claimed, len(outPacket))
			return
		}
	case 6:
		if len(outPacket) < 48 {
			log.Error(tag, "dns: short v6 packet %s len=%d", name, len(outPacket))
			return
		}
		// IPv6 payload length is everything after the 40-byte header
		claimedPayload := int(binary.BigEndian.Uint16(outPacket[4:6]))
		if claimedPayload != len(outPacket)-40 {
			log.Error(tag, "dns: v6 len mismatch %s claimedPayload=%d actualPayload=%d",
				name, claimedPayload, len(outPacket)-40)
			return
		}
	default:
		log.Error(tag, "dns: bad IP version %d for %s", orig.IPVersion, name)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	if _, err := f.realTUN.Write([][]byte{outPacket}, 0); err != nil {
		log.Error(tag, "dns: write %s len=%d mtu=%d: %v", name, len(outPacket), mtu, err)
		return
	}
	// Disable logging for domain names for now
	//log.Debug(tag, "dns: replied %s (%d bytes)", name, len(outPacket))
}

var _ awgtun.Device = (*WrapperTUN)(nil)
