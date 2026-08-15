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

type Transport struct {
	Servers     []string // pre-resolved servers
	Network     string   // udp (default) or tcp
	Timeout     time.Duration
	Dialer      *net.Dialer
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	client      *dns.Client
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

// normalizePlainServer makes host:port that net.Dial accepts
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

func (t *Transport) init() {
	if t.client != nil {
		return
	}
	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: t.Timeout}
	}
	t.client = &dns.Client{
		Net:     t.Network,
		Dialer:  dialer,
		Timeout: t.Timeout,
		UDPSize: 4096,
	}
}

func (t *Transport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(t.Servers) == 0 {
		return nil, fmt.Errorf("plain: no servers configured")
	}
	t.init()

	var lastErr error
	for _, server := range t.Servers {
		m, err := t.exchangeOne(ctx, msg, server)
		if err != nil {
			log.Debug("PlainDNS", "server %s: %v", server, err)
			lastErr = err
			continue
		}
		if m == nil {
			lastErr = fmt.Errorf("plain: empty response from %s", server)
			continue
		}
		// Any DNS response is valid NOERROR, NXDOMAIN, SERVFAIL, etc
		return m, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("plain: all servers failed")
	}
	return nil, lastErr
}

func (t *Transport) exchangeOne(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	if t.DialContext == nil {
		m, _, err := t.client.ExchangeContext(ctx, msg, server)
		return m, err
	}
	network := t.Network
	if network == "" {
		network = "udp"
	}
	c, err := t.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	conn := &dns.Conn{Conn: c}
	if err := conn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return conn.ReadMsg()
}

func (t *Transport) Close() error { return nil }

var _ transport.Transport = (*Transport)(nil)
