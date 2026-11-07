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

// maxPooledIdle is how long a warm DoT connection may sit unused.
const maxPooledIdle = 2 * time.Second

type idleConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

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
	pools  map[string]chan *idleConn // server -> idle connections
	closed bool
}

func New(servers []string, serverName string) *Transport {
	return &Transport{
		Servers:    servers,
		ServerName: serverName,
		Timeout:    6 * time.Second,
		pools:      make(map[string]chan *idleConn),
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
// pool, avoiding a fresh TCP+TLS handshake on every query.
func (t *Transport) exchangePooled(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	conn, reused, err := t.checkoutConn(ctx, server)
	if err != nil {
		return nil, err
	}

	m, err := t.exchangeOnConn(ctx, conn, msg)
	if err != nil {
		_ = conn.Close()
		// A reused socket can fail because the server already closed it. The
		// other idle sockets from that burst usually died with it, so drop
		// them and dial once.
		if !reused || ctx.Err() != nil {
			return nil, err
		}
		t.discardIdle(server)
		fresh, dialErr := t.dialConn(ctx, server)
		if dialErr != nil {
			return nil, dialErr
		}
		m, err = t.exchangeOnConn(ctx, fresh, msg)
		if err != nil {
			_ = fresh.Close()
			return nil, err
		}
		return t.finishConn(ctx, server, fresh, m)
	}
	return t.finishConn(ctx, server, conn, m)
}

// finishConn returns msg to the caller. The socket is pooled only when ctx is
// still active. A read can succeed and the context can end immediately
// afterward. That answer is still valid.
func (t *Transport) finishConn(ctx context.Context, server string, conn *dns.Conn, msg *dns.Msg) (*dns.Msg, error) {
	if ctx.Err() != nil {
		_ = conn.Close()
		return msg, nil
	}
	t.releaseConn(server, conn)
	return msg, nil
}

// exchangeOnConn honors ctx in addition to the transport's own Timeout, so a
// caller that times out or cancels early isn't left blocked on this connection's I/O
// for up to the full t.Timeout regardless of what the caller actually asked
func (t *Transport) exchangeOnConn(ctx context.Context, conn *dns.Conn, msg *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(t.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	// Stopped is closed only after the watcher has chosen a branch.
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			// Unblocks WriteMsg/ReadMsg immediately instead of waiting out
			// the socket deadline as the caller has already given up.
			_ = conn.Close()
		case <-stop:
		}
	}()

	writeErr := conn.WriteMsg(msg)
	var resp *dns.Msg
	var readErr error
	if writeErr == nil {
		resp, readErr = conn.ReadMsg()
	}
	close(stop)
	<-stopped
	if writeErr != nil {
		return nil, writeErr
	}
	return resp, readErr
}

func (t *Transport) checkoutConn(ctx context.Context, server string) (conn *dns.Conn, reused bool, err error) {
	pool := t.poolFor(server)
	for {
		select {
		case c := <-pool:
			if c == nil || c.conn == nil {
				return nil, false, fmt.Errorf("dot: transport closed")
			}
			if time.Since(c.lastUsed) > maxPooledIdle {
				_ = c.conn.Close()
				continue
			}
			return c.conn, true, nil
		default:
			conn, err = t.dialConn(ctx, server)
			return conn, false, err
		}
	}
}

func (t *Transport) dialConn(ctx context.Context, server string) (*dns.Conn, error) {
	raw, err := t.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: t.ServerName,
		MinVersion: tls.VersionTLS12,
		RootCAs:    t.RootCAs,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &dns.Conn{Conn: tlsConn}, nil
}

func (t *Transport) poolFor(server string) chan *idleConn {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	pool := t.pools[server]
	if pool == nil {
		pool = make(chan *idleConn, maxIdleConnsPerServer)
		t.pools[server] = pool
	}
	return pool
}

// releaseConn returns conn to the idle pool, or closes it if the transport has
// been closed or the pool for this server is already full.
func (t *Transport) releaseConn(server string, conn *dns.Conn) {
	t.poolMu.Lock()
	pool := t.pools[server]
	pooled := false
	if !t.closed && pool != nil {
		select {
		case pool <- &idleConn{conn: conn, lastUsed: time.Now()}:
			pooled = true
		default:
		}
	}
	t.poolMu.Unlock()
	if !pooled {
		_ = conn.Close()
	}
}

// discardIdle closes every idle connection for server.
func (t *Transport) discardIdle(server string) {
	t.poolMu.Lock()
	pool := t.pools[server]
	t.poolMu.Unlock()
	if pool == nil {
		return
	}
	for {
		select {
		case c := <-pool:
			// A closed pool delivers nil forever. Stop instead of spinning.
			if c == nil || c.conn == nil {
				return
			}
			_ = c.conn.Close()
		default:
			return
		}
	}
}

func (t *Transport) Close() error {
	t.poolMu.Lock()
	t.closed = true
	pools := t.pools
	t.pools = make(map[string]chan *idleConn)
	t.poolMu.Unlock()

	for _, pool := range pools {
		close(pool)
		for c := range pool {
			if c != nil && c.conn != nil {
				_ = c.conn.Close()
			}
		}
	}
	return nil
}

var _ transport.Transport = (*Transport)(nil)
