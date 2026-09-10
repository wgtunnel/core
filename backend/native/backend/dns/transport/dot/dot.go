package dot

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport"
)

// maxIdleConnsPerServer caps how many idle TLS connections are kept warm per
// upstream server. Bounded so a burst of concurrent lookups doesn't accumulate connections indefinitely.
const maxIdleConnsPerServer = 8

type Transport struct {
	Servers     []string // should be pre-resolved
	ServerName  string   // TLS SNI
	Timeout     time.Duration
	Dialer      *net.Dialer
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	RootCAs     *x509.CertPool // nil = system roots

	initOnce sync.Once
	client   *dns.Client

	poolMu sync.Mutex
	pools  map[string]chan *dns.Conn // server -> idle connections
	closed bool
}

func New(servers []string, serverName string) *Transport {
	return &Transport{
		Servers:    servers,
		ServerName: serverName,
		Timeout:    6 * time.Second,
		pools:      make(map[string]chan *dns.Conn),
	}
}

func (t *Transport) Type() string { return "dot" }

// init lazily builds the fallback dns.Client used only when no DialContext is supplied
func (t *Transport) init() {
	t.initOnce.Do(func() {
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
				RootCAs:    t.RootCAs,
			},
		}
	})
}

func (t *Transport) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(t.Servers) == 0 {
		return nil, fmt.Errorf("dot: no servers configured")
	}

	var lastErr error
	for i, server := range t.Servers {
		attemptCtx, cancel := transport.PerAttemptContext(ctx, len(t.Servers)-i)
		var m *dns.Msg
		var err error
		if t.DialContext != nil {
			m, err = t.exchangePooled(attemptCtx, msg, server)
		} else {
			t.init()
			m, _, err = t.client.ExchangeContext(attemptCtx, msg, server)
		}
		cancel()
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

// exchangePooled reuses a warm TLS connection to server when one is idle in the
// pool, avoiding a fresh TCP+TLS handshake on every query
func (t *Transport) exchangePooled(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	conn, reused, err := t.checkoutConn(ctx, server)
	if err != nil {
		return nil, err
	}

	m, err := t.exchangeOnConn(conn, msg)
	if err != nil {
		_ = conn.Close()
		// A pooled connection may have been closed/idled-out by the server
		// between checkout and use; retry once against a fresh connection
		// before giving up, but only for the reused case to avoid masking a
		// real fresh-dial failure as a silent extra round trip.
		if reused {
			conn, _, dialErr := t.checkoutConn(ctx, server)
			if dialErr != nil {
				return nil, err
			}
			m, err = t.exchangeOnConn(conn, msg)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			t.releaseConn(server, conn)
			return m, nil
		}
		return nil, err
	}

	t.releaseConn(server, conn)
	return m, nil
}

func (t *Transport) exchangeOnConn(conn *dns.Conn, msg *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(t.Timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return conn.ReadMsg()
}

func (t *Transport) checkoutConn(ctx context.Context, server string) (conn *dns.Conn, reused bool, err error) {
	t.poolMu.Lock()
	pool := t.pools[server]
	if pool == nil {
		pool = make(chan *dns.Conn, maxIdleConnsPerServer)
		t.pools[server] = pool
	}
	t.poolMu.Unlock()

	select {
	case c := <-pool:
		return c, true, nil
	default:
	}

	raw, err := t.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, false, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: t.ServerName,
		MinVersion: tls.VersionTLS12,
		RootCAs:    t.RootCAs,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, false, err
	}
	return &dns.Conn{Conn: tlsConn}, false, nil
}

// releaseConn returns conn to the idle pool, or closes it if the transport has
// been closed or the pool for this server is already full.
func (t *Transport) releaseConn(server string, conn *dns.Conn) {
	t.poolMu.Lock()
	pool := t.pools[server]
	closed := t.closed
	t.poolMu.Unlock()

	if closed || pool == nil {
		_ = conn.Close()
		return
	}
	select {
	case pool <- conn:
	default:
		_ = conn.Close()
	}
}

func (t *Transport) Close() error {
	t.poolMu.Lock()
	t.closed = true
	pools := t.pools
	t.pools = make(map[string]chan *dns.Conn)
	t.poolMu.Unlock()

	for _, pool := range pools {
		close(pool)
		for conn := range pool {
			_ = conn.Close()
		}
	}
	return nil
}

var _ transport.Transport = (*Transport)(nil)
