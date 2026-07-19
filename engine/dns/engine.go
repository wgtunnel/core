package dns

import (
	"context"
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// Engine is the DNS Engine used by the TUN
type Engine struct {
	mu         sync.RWMutex
	transports map[string]Transport
	router     Router
}

func NewEngine() *Engine {
	return &Engine{
		transports: make(map[string]Transport),
	}
}

func (e *Engine) RegisterTransport(tag string, t Transport) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.transports[tag] = t
}

func (e *Engine) GetTransport(tag string) (Transport, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	t, ok := e.transports[tag]
	return t, ok
}

func (e *Engine) SetRouter(r Router) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.router = r
}

func (e *Engine) SetLocalNetworkHandle(handle int64) {
	t, ok := e.GetTransport("local")
	if !ok {
		return
	}
	if lt, ok := t.(interface{ SetNetworkHandle(int64) }); ok {
		lt.SetNetworkHandle(handle)
	}
}

// Exchange is the main entry point (called when hijacking DNS from TUN)
func (e *Engine) Exchange(ctx context.Context, msg *dns.Msg) (*ExchangeResult, error) {
	e.mu.RLock()
	r := e.router
	e.mu.RUnlock()

	if r == nil {
		return nil, fmt.Errorf("dns: no router configured")
	}
	return r.Exchange(ctx, msg)
}

func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var firstErr error
	for _, t := range e.transports {
		if err := t.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.router != nil {
		if err := e.router.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
