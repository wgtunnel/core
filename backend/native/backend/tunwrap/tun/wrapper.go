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
	suffixes         []string
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
	suffixes []string,
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
	sfx := append([]string(nil), suffixes...)
	return &WrapperTUN{
		realTUN:          real,
		dns:              dnsEngine,
		fakeDNSv4:        v4,
		fakeDNSv6:        v6, // zero Addr if unused — IsValid() == false
		foreignDNSPolicy: foreignDnsPolicy,
		suffixes:         sfx,
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

	policy := normalizeForeignDNSPolicy(f.foreignDNSPolicy)

	// TCP/53 Prefer not blocking suffix-matched names, otherwise
	// apply foreign policy by destination
	if p.Protocol == 6 && p.DstPort == 53 {
		if _, ok := f.passthroughDNS[p.DstIP]; ok {
			return false
		}
		toFake := isDNSQueryToFake(p, f.fakeDNSv4, f.fakeDNSv6)
		if !toFake && policy == "allow" {
			//log.Debug(tag, "dns: allow tcp/53 %s to %s, pass", p.SrcIP, p.DstIP)
			return false
		}
		if !toFake {
			//log.Debug(tag, "dns: block tcp/53 %s to %s, drop", p.SrcIP, p.DstIP)
			return true
		}
		// FakeDNS over TCP, drop
		//log.Debug(tag, "dns: drop tcp/53 fake %s to %s", p.SrcIP, p.DstIP)
		return true
	}

	if p.Protocol != 17 || p.DstPort != 53 {
		return false
	}

	if _, ok := f.passthroughDNS[p.DstIP]; ok {
		return false
	}

	if len(p.Payload) == 0 {
		log.Debug(tag, "dns: empty udp payload, drop")
		return true
	}

	qname, qok := dnsQuestionName(p.Payload)
	toFake := isDNSQueryToFake(p, f.fakeDNSv4, f.fakeDNSv6)
	suffixHit := qok && tunDns.NameMatchesSuffixes(qname, f.suffixes)

	// Split suffixes win over foreign policy: always hijack matching names,
	// even when the client targeted 8.8.8.8 / etc.
	switch {
	case suffixHit:
		//log.Debug(tag, "dns: suffix-match name=%s dest=%s → hijack", qname, p.DstIP)
	case toFake:
		//log.Debug(tag, "dns: fake name=%s dest=%s → hijack", emptyName(qname, qok), p.DstIP)
	default:
		switch policy {
		case "allow":
			//log.Debug(tag, "dns: allow name=%s dest=%s → pass", emptyName(qname, qok), p.DstIP)
			return false
		case "drop":
			//log.Debug(tag, "dns: block name=%s dest=%s → drop", emptyName(qname, qok), p.DstIP)
			return true
		default: // redirect
			//log.Debug(tag, "dns: redirect name=%s dest=%s → hijack", emptyName(qname, qok), p.DstIP)
		}
	}

	select {
	case f.dnsSem <- struct{}{}:
	default:
		log.Debug(tag, "dns: drop under load name=%s dest=%s", emptyName(qname, qok), p.DstIP)
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

func dnsQuestionName(payload []byte) (string, bool) {
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil || len(msg.Question) == 0 {
		return "", false
	}
	return msg.Question[0].Name, true
}

func emptyName(name string, ok bool) string {
	if !ok || name == "" {
		return "?"
	}
	return name
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
		log.Debug(tag, "dns: reply name=%s rcode=%d answers=%d (cache)", q.Name, cached.Rcode, len(cached.Answer))
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
				log.Debug(tag, "dns: reply name=%s rcode=SERVFAIL (local no handle)", q.Name)
				ttl = 30 * time.Second // give more breathing room when handle is missing
			} else {
				log.Error(tag, "dns: exchange name=%s err=%v → SERVFAIL", q.Name, err)
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
	log.Debug(tag, "dns: reply name=%s rcode=%d answers=%d", q.Name, resp.Rcode, len(resp.Answer))
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

// normalizeForeignDNSPolicy maps Kotlin/native wire values to allow|drop|redirect.
func normalizeForeignDNSPolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "allow":
		return "allow"
	case "drop", "block":
		return "drop"
	default:
		return "redirect"
	}
}

var _ awgtun.Device = (*WrapperTUN)(nil)
