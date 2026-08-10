package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport"
)

type Transport struct {
	Servers    []string // should be pre-resolved
	ServerName string   // TLS SNI
	Timeout    time.Duration
	Dialer     *net.Dialer

	client *dns.Client
}

func New(servers []string, serverName string) *Transport {
	return &Transport{
		Servers:    servers,
		ServerName: serverName,
		Timeout:    6 * time.Second,
	}
}

func (t *Transport) Type() string { return "dot" }

func (t *Transport) init() {
	if t.client != nil {
		return
	}
	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: t.Timeout}
	}
	t.client = &dns.Client{
		Net:     "tcp-tls",
		Dialer:  dialer,
		Timeout: t.Timeout,
		TLSConfig: &tls.Config{
			ServerName: t.ServerName,
			MinVersion: tls.VersionTLS12,
		},
	}
}

func (t *Transport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(t.Servers) == 0 {
		return nil, fmt.Errorf("dot: no servers configured")
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
			lastErr = fmt.Errorf("dot: empty response from %s", server)
			continue
		}
		return m, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dot: all servers failed")
	}
	return nil, lastErr
}

func (t *Transport) Close() error { return nil }

var _ transport.Transport = (*Transport)(nil)
