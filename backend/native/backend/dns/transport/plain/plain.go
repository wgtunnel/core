package plain

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport"
)

type Transport struct {
	Servers []string // pre-resolved servers
	Network string   // udp (default) or tcp
	Timeout time.Duration
	Dialer  *net.Dialer
	client  *dns.Client
}

func New(servers []string, network string) *Transport {
	if network == "" {
		network = "udp"
	}
	return &Transport{
		Servers: servers,
		Network: network,
		Timeout: 5 * time.Second,
	}
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
		m, _, err := t.client.ExchangeContext(ctx, msg, server)
		if err != nil {
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

func (t *Transport) Close() error { return nil }

var _ transport.Transport = (*Transport)(nil)
