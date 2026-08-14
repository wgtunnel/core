package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/wgtunnel/backend/dns/transport"
	"github.com/wgtunnel/backend/dns/transport/doh"
	"github.com/wgtunnel/backend/dns/transport/dot"
	"github.com/wgtunnel/backend/dns/transport/local"
	"github.com/wgtunnel/backend/dns/transport/plain"
	"github.com/wgtunnel/backend/log"
)

const tag = "Bootstrap"

// Resolve runs a one-shot Ipv4 and IPv6 lookup using options
func Resolve(ctx context.Context, host string, opts Options) (v4, v6 []netip.Addr, err error) {
	opts = opts.withDefaults()
	log.Debug(tag, "lookup host=%s protocol=%s upstream=%s", host, opts.Protocol, opts.ResolvedUpstream)

	tr, err := newTransport(opts)
	if err != nil {
		log.Error(tag, "transport host=%s protocol=%s: %v", host, opts.Protocol, err)
		return nil, nil, err
	}
	defer tr.Close()

	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msgA.SetEdns0(4096, true)
	if resp, errA := tr.Exchange(ctx, msgA); errA == nil {
		v4 = parseAnswers(resp, dns.TypeA)
	} else {
		err = errA
	}

	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	msgAAAA.SetEdns0(4096, true)
	if resp, errAAAA := tr.Exchange(ctx, msgAAAA); errAAAA == nil {
		v6 = parseAnswers(resp, dns.TypeAAAA)
		err = nil
	} else if len(v4) == 0 {
		err = errAAAA
	}

	if len(v4) == 0 && len(v6) == 0 {
		log.Error(tag, "no addresses for %s protocol=%s: %v", host, opts.Protocol, err)
		return nil, nil, fmt.Errorf("no addresses for %s: %v", host, err)
	}
	log.Debug(tag, "lookup host=%s protocol=%s → v4=%s v6=%s", host, opts.Protocol, joinAddrs(v4), joinAddrs(v6))
	return v4, v6, nil
}

func newTransport(opts Options) (transport.Transport, error) {
	switch strings.ToLower(opts.Protocol) {
	case "doh":
		return newDoHTransport(opts.OriginalUpstream, opts.ResolvedUpstream, opts.Dialer)
	case "dot":
		return newDoTTransport(opts.OriginalUpstream, opts.ResolvedUpstream, opts.Dialer)
	case "local":
		return local.NewLocalTransport(), nil
	default:
		return newPlainTransport(opts.ResolvedUpstream, opts.Dialer)
	}
}

func newPlainTransport(resolved string, dialer *net.Dialer) (transport.Transport, error) {
	servers := splitUpstreams(resolved)
	if len(servers) == 0 {
		return nil, fmt.Errorf("plain bootstrap: no servers")
	}
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			servers[i] = net.JoinHostPort(s, "53")
		}
	}
	tr := plain.New(servers, "udp")
	tr.Dialer = dialer
	return tr, nil
}

func newDoTTransport(original, resolved string, dialer *net.Dialer) (transport.Transport, error) {
	servers := splitUpstreams(resolved)
	if len(servers) == 0 {
		return nil, fmt.Errorf("dot bootstrap: no servers")
	}
	sni, defPort, err := net.SplitHostPort(original)
	if err != nil {
		sni, defPort = original, "853"
	}
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			servers[i] = net.JoinHostPort(s, defPort)
		}
	}
	tr := dot.New(servers, sni)
	tr.Dialer = dialer
	return tr, nil
}

func newDoHTransport(original, resolved string, dialer *net.Dialer) (transport.Transport, error) {
	urls := splitUpstreams(resolved)
	if len(urls) == 0 {
		return nil, fmt.Errorf("doh bootstrap: no urls")
	}
	orig := original
	if !strings.HasPrefix(orig, "https://") && !strings.HasPrefix(orig, "http://") {
		orig = "https://" + orig
	}
	u, err := url.Parse(orig)
	if err != nil {
		return nil, err
	}
	tr := doh.New(urls, u.Hostname())
	tr.Timeout = 5 * time.Second
	tr.DialContext = dialer.DialContext
	return tr, nil
}

func parseAnswers(msg *dns.Msg, qtype uint16) []netip.Addr {
	var out []netip.Addr
	for _, ans := range msg.Answer {
		switch qtype {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				if ip, e := netip.ParseAddr(a.A.String()); e == nil {
					out = append(out, ip)
				}
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				if ip, e := netip.ParseAddr(aaaa.AAAA.String()); e == nil {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

func splitUpstreams(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, ",") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func formatResult(v4, v6 []netip.Addr) string {
	return fmt.Sprintf("v4=%s;v6=%s", joinAddrs(v4), joinAddrs(v6))
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ",")
}
