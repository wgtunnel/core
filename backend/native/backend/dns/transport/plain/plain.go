package plain

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport"
	"github.com/wgtunnel/backend/log"
)

// DefaultEDNSSize is the UDP payload advertised when the path MTU is unknown.
// 1232 fits an IPv6 datagram on a 1280-byte path (typical WireGuard inner MTU).
const DefaultEDNSSize = 1232

type Transport struct {
	Servers     []string // pre-resolved servers
	Network     string   // udp (default) or tcp
	Timeout     time.Duration
	Dialer      *net.Dialer
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// UDPSize is the EDNS0 requestor payload and the UDP read buffer.
	// Zero uses DefaultEDNSSize.
	UDPSize uint16
}

func New(servers []string, network string) *Transport {
	if network == "" {
		network = "udp"
	}
	normalized := make([]string, 0, len(servers))
	for _, s := range servers {
		if n := normalizePlainServer(s); n != "" {
			normalized = append(normalized, n)
		}
	}
	log.Debug("PlainDNS", "upstream order=%v", normalized)
	return &Transport{
		Servers: normalized,
		Network: network,
		Timeout: 5 * time.Second,
	}
}

// EDNSSizeForMTU is the EDNS0 UDP payload that fits one unfragmented
// IPv6 packet on a path of the given MTU, capped at DefaultEDNSSize.
func EDNSSizeForMTU(mtu int) uint16 {
	if mtu <= 0 {
		return DefaultEDNSSize
	}
	n := mtu - 48 // IPv6 header + UDP
	if n > DefaultEDNSSize {
		n = DefaultEDNSSize
	}
	if n < dns.MinMsgSize {
		n = dns.MinMsgSize
	}
	return uint16(n)
}

func normalizePlainServer(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s + ":53"
	}
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	return net.JoinHostPort(s, "53")
}

func (t *Transport) Type() string { return "plain" }

func (t *Transport) ednsSize() uint16 {
	if t != nil && t.UDPSize >= dns.MinMsgSize {
		return t.UDPSize
	}
	return DefaultEDNSSize
}

func (t *Transport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(t.Servers) == 0 {
		return nil, fmt.Errorf("plain: no servers configured")
	}

	var lastErr error
	for i, server := range t.Servers {
		attemptCtx, cancel := transport.PerAttemptContext(ctx, len(t.Servers)-i)
		m, err := t.exchangeOne(attemptCtx, msg, server)
		cancel()
		if err != nil {
			log.Debug("PlainDNS", "server %s: %v", server, err)
			lastErr = err
			continue
		}
		if m == nil {
			lastErr = fmt.Errorf("plain: empty response from %s", server)
			continue
		}
		return m, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("plain: all servers failed")
	}
	return nil, lastErr
}

func (t *Transport) exchangeOne(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	q := clampEDNS(msg, t.ednsSize())
	network := t.Network
	if network == "" {
		network = "udp"
	}
	if network == "tcp" || network == "tcp-tls" {
		return t.roundTrip(ctx, network, q, server)
	}

	resp, err := t.roundTrip(ctx, "udp", q, server)
	if !needTCPFallback(resp, err) {
		return resp, err
	}
	tcpResp, tcpErr := t.roundTrip(ctx, "tcp", q, server)
	if tcpErr == nil {
		return tcpResp, nil
	}
	if resp != nil && err == nil {
		return resp, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, tcpErr
}

func needTCPFallback(resp *dns.Msg, err error) bool {
	if resp != nil && resp.Truncated {
		return true
	}
	return err != nil && resp != nil
}

func (t *Transport) roundTrip(ctx context.Context, network string, msg *dns.Msg, server string) (*dns.Msg, error) {
	if t.DialContext != nil {
		c, err := t.DialContext(ctx, network, server)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(deadline)
		}
		conn := &dns.Conn{Conn: c}
		if isUDPNetwork(network) {
			conn.UDPSize = t.ednsSize()
		}
		if err := conn.WriteMsg(msg); err != nil {
			return nil, err
		}
		return conn.ReadMsg()
	}

	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: t.Timeout}
	}
	client := &dns.Client{
		Net:     network,
		Dialer:  dialer,
		Timeout: t.Timeout,
		UDPSize: t.ednsSize(),
	}
	m, _, err := client.ExchangeContext(ctx, msg, server)
	return m, err
}

func isUDPNetwork(network string) bool {
	return network == "udp" || network == "udp4" || network == "udp6"
}

// clampEDNS copies msg and replaces any stub OPT with our path-sized payload.
func clampEDNS(msg *dns.Msg, size uint16) *dns.Msg {
	var q *dns.Msg
	if msg != nil {
		q = msg.Copy()
	}
	if q == nil {
		q = new(dns.Msg)
	}
	extra := make([]dns.RR, 0, len(q.Extra))
	for _, rr := range q.Extra {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		extra = append(extra, rr)
	}
	q.Extra = extra
	if size < dns.MinMsgSize {
		size = dns.MinMsgSize
	}
	q.SetEdns0(size, false)
	return q
}

func (t *Transport) Close() error { return nil }

var _ transport.Transport = (*Transport)(nil)
