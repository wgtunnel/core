package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Router selects which Transport handles a query
type Router interface {
	Exchange(ctx context.Context, msg *dns.Msg) (*ExchangeResult, error)
	Close() error
}

// SimpleRouter is a first-match-wins DNS router
type SimpleRouter struct {
	rules  []Rule
	final  string
	engine *Engine
}

func NewSimpleRouter(engine *Engine, final string) *SimpleRouter {
	return &SimpleRouter{
		engine: engine,
		final:  final,
	}
}

func (r *SimpleRouter) AddRule(rule Rule) {
	r.rules = append(r.rules, rule)
}

func (r *SimpleRouter) Exchange(ctx context.Context, msg *dns.Msg) (*ExchangeResult, error) {
	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("dns: empty question")
	}

	q := msg.Question[0]
	name := normalizeDNSName(q.Name)

	for _, rule := range r.rules {
		if !matchRule(rule, name, q.Qtype) {
			continue
		}
		t, ok := r.engine.GetTransport(rule.Transport)
		if !ok {
			return nil, fmt.Errorf("dns: transport %q not found", rule.Transport)
		}
		resp, err := t.Exchange(ctx, msg)
		if err != nil {
			return nil, err
		}
		return &ExchangeResult{Msg: resp, DisableCache: rule.DisableCache}, nil
	}

	t, ok := r.engine.GetTransport(r.final)
	if !ok {
		return nil, fmt.Errorf("dns: final transport %q not found", r.final)
	}
	resp, err := t.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	return &ExchangeResult{Msg: resp, DisableCache: false}, nil
}

func (r *SimpleRouter) Close() error { return nil }

func normalizeDNSName(name string) string {
	name = strings.ToLower(name)
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func matchRule(rule Rule, name string, qtype uint16) bool {
	// name must already be normalized

	if len(rule.QueryTypes) > 0 {
		found := false
		for _, t := range rule.QueryTypes {
			if t == qtype {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(rule.Domains) == 0 {
		return true // match all names
	}

	for _, d := range rule.Domains {
		if matchDomain(name, d) {
			return true
		}
	}
	return false
}

// matchDomain reports whether normalized name matches pattern
func matchDomain(name, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}

	// For suffix style
	suffixOnly := strings.HasPrefix(pattern, ".")
	pattern = strings.TrimPrefix(pattern, ".")
	if !strings.HasSuffix(pattern, ".") {
		pattern += "."
	}

	if name == pattern {
		return true
	}
	// Subdomain
	if strings.HasSuffix(name, "."+pattern) {
		return true
	}
	if suffixOnly {
		return false
	}
	return false
}

var _ Router = (*SimpleRouter)(nil)
