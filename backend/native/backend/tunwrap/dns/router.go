package dns

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/log"
)

const routerTag = "DnsRouter"

// localTransportName is the tag used for the transport that dials the
// physical underlay interface directly, bypassing the tunnel. When
// kill switch is enabled, we don't allow this bypass to happen
const localTransportName = "local"

// ErrLocalBlockedByKillSwitch is returned instead of dialing the local
// transport while the kill switch is enabled
var ErrLocalBlockedByKillSwitch = fmt.Errorf("dns: local transport blocked by kill switch")

// Router selects which Transport handles a query
type Router interface {
	Exchange(ctx context.Context, msg *dns.Msg) (*ExchangeResult, error)
	Close() error
}

// SimpleRouter is a first-match-wins DNS router
type SimpleRouter struct {
	rules            []Rule
	final            string
	engine           *Engine
	killSwitchActive func() bool
}

// NewSimpleRouter builds a router. killSwitchActive, when non-nil, is
// consulted on every query that would otherwise dial the local (underlay)
// transport; when it reports true, the local transport is refused instead
// of dialed.
func NewSimpleRouter(engine *Engine, final string, killSwitchActive func() bool) *SimpleRouter {
	if killSwitchActive == nil {
		killSwitchActive = func() bool { return false }
	}
	return &SimpleRouter{
		engine:           engine,
		final:            final,
		killSwitchActive: killSwitchActive,
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
		if rule.Transport == localTransportName && r.killSwitchActive() {
			log.Debug(routerTag, "route name=%s to transport=%s (suffix rule): blocked by kill switch", name, rule.Transport)
			return nil, ErrLocalBlockedByKillSwitch
		}
		t, ok := r.engine.GetTransport(rule.Transport)
		if !ok {
			return nil, fmt.Errorf("dns: transport %q not found", rule.Transport)
		}
		log.Debug(routerTag, "route name=%s to transport=%s (suffix rule)", name, rule.Transport)
		resp, err := t.Exchange(ctx, msg)
		if err != nil {
			log.Error(routerTag, "exchange name=%s transport=%s (suffix rule): %v", name, rule.Transport, err)
			return nil, err
		}
		return &ExchangeResult{Msg: resp, DisableCache: rule.DisableCache}, nil
	}

	if r.final == localTransportName && r.killSwitchActive() {
		log.Debug(routerTag, "route name=%s to transport=%s (default): blocked by kill switch", name, r.final)
		return nil, ErrLocalBlockedByKillSwitch
	}
	t, ok := r.engine.GetTransport(r.final)
	if !ok {
		return nil, fmt.Errorf("dns: final transport %q not found", r.final)
	}
	log.Debug(routerTag, "route name=%s to transport=%s (default)", name, r.final)
	resp, err := t.Exchange(ctx, msg)
	if err != nil {
		log.Error(routerTag, "exchange name=%s transport=%s (default): %v", name, r.final, err)
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
		found := slices.Contains(rule.QueryTypes, qtype)
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

// NameMatchesSuffixes reports whether name matches any configured split suffix.
// name may be raw or already normalized.
func NameMatchesSuffixes(name string, suffixes []string) bool {
	if len(suffixes) == 0 || strings.TrimSpace(name) == "" {
		return false
	}
	n := normalizeDNSName(name)
	for _, s := range suffixes {
		if matchDomain(n, s) {
			return true
		}
	}
	return false
}

// matchDomain reports whether normalized name matches pattern.
func matchDomain(name, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}

	pattern = strings.TrimPrefix(pattern, ".")
	if !strings.HasSuffix(pattern, ".") {
		pattern += "."
	}

	if name == pattern {
		return true
	}
	// Subdomain / suffix: home.local. matches local.
	return strings.HasSuffix(name, "."+pattern)
}

var _ Router = (*SimpleRouter)(nil)
