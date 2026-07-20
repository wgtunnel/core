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
	URLs        []string // full URLs, should be pre-resolved
	ServerName  string   // SNI + Host header
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

func New(rawURLs []string, serverName string) *Transport {
	return &Transport{
		URLs:       rawURLs,
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
	if len(t.URLs) == 0 {
		return nil, fmt.Errorf("doh: no urls configured")
	}
	t.init()

	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: pack: %w", err)
	}

	var lastErr error
	for _, rawURL := range t.URLs {
		out, err := t.exchangeOne(ctx, wire, rawURL)
		if err != nil {
			lastErr = err
			continue
		}
		return out, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("doh: all urls failed")
	}
	return nil, lastErr
}

func (t *Transport) exchangeOne(ctx context.Context, wire []byte, rawURL string) (*dns.Msg, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("doh: request %s: %w", rawURL, err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if t.ServerName != "" {
		req.Host = t.ServerName
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: do %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: status %d from %s", resp.StatusCode, rawURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, fmt.Errorf("doh: read %s: %w", rawURL, err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: unpack %s: %w", rawURL, err)
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
