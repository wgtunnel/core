package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	coredns "github.com/wgtunnel/core/engine/dns"
	"github.com/wgtunnel/core/log"
)

type Transport struct {
	URL         string // full URL, should be pre-resolved
	ServerName  string // SNI + Host header
	Timeout     time.Duration
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	client *http.Client
	Logger *log.Logger
}

func (t *Transport) log() *log.Logger {
	if t.Logger != nil {
		return t.Logger
	}
	return log.Nop()
}

func New(rawURL string, serverName string) *Transport {
	return &Transport{
		URL:        rawURL,
		ServerName: serverName,
		Timeout:    5 * time.Second,
	}
}

func (t *Transport) Type() string { return "doh" }

func (t *Transport) init() {
	if t.client != nil {
		return
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: t.ServerName,
			MinVersion: tls.VersionTLS12,
		},
	}
	if t.DialContext != nil {
		tr.DialContext = t.DialContext
	}
	t.client = &http.Client{
		Timeout:   t.Timeout,
		Transport: tr,
	}
}

func (t *Transport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	t.init()

	if len(msg.Question) > 0 {
		t.log().Verbosef("DoH Exchange via %s for %s", t.URL, msg.Question[0].Name)
	}

	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: pack: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("doh: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if t.ServerName != "" {
		req.Host = t.ServerName
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, fmt.Errorf("doh: read: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: unpack: %w", err)
	}
	return out, nil
}

func (t *Transport) Close() error {
	if t.client != nil {
		t.client.CloseIdleConnections()
	}
	return nil
}

var _ coredns.Transport = (*Transport)(nil)
