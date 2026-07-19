package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	coredns "github.com/wgtunnel/core/engine/dns"
	"github.com/wgtunnel/core/log"
)

type Transport struct {
	Servers    []string // should be pre-resolved
	ServerName string   // TLS SNI
	Timeout    time.Duration
	Dialer     *net.Dialer
	Logger     *log.Logger

	client *dns.Client
}

func New(servers []string, serverName string) *Transport {
	return &Transport{
		Servers:    servers,
		ServerName: serverName,
		Timeout:    6 * time.Second,
		Logger:     log.Nop(),
	}
}

func (t *Transport) Type() string { return "dot" }

func (t *Transport) log() *log.Logger {
	if t.Logger != nil {
		return t.Logger
	}
	return log.Nop()
}

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

	if len(msg.Question) > 0 {
		t.log().Verbosef("dot exchange via %s for %s", t.Servers[0], msg.Question[0].Name)
	}

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

var _ coredns.Transport = (*Transport)(nil)
