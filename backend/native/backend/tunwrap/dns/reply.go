package dns

import (
	"fmt"

	"github.com/miekg/dns"
)

func MaxPayload(mtu, ipVersion int) int {
	if mtu <= 0 {
		mtu = 1280
	}
	overhead := 28 // IPv4 header + UDP
	if ipVersion == 6 {
		overhead = 48
	}
	n := mtu - overhead
	if n < 12 {
		return 12
	}
	return n
}

// PackForTUN shapes a FakeDNS reply so it fits one unfragmented TUN packet:
// drop additionals and non-QTYPE answers, then Truncate on RR boundaries.
func PackForTUN(resp *dns.Msg, maxPayload int) ([]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("nil dns message")
	}
	qtypeRRs := qtypeAnswers(resp)
	minimizeReply(resp)

	b, err := resp.Pack()
	if err != nil {
		return nil, err
	}
	if len(b) <= maxPayload {
		return b, nil
	}

	resp.Truncate(maxPayload)
	b, err = resp.Pack()
	if err != nil {
		return nil, err
	}
	if len(b) <= maxPayload && (len(qtypeRRs) == 0 || hasQType(resp, qtypeOf(resp))) {
		return b, nil
	}

	// Truncate dropped the QTYPE (CNAME chain filled the budget). Flatten to QTYPE RRs.
	if len(qtypeRRs) > 0 {
		resp.Truncated = false
		resp.Answer = qtypeRRs
		resp.Ns = nil
		resp.Extra = nil
		b, err = resp.Pack()
		if err != nil {
			return nil, err
		}
		if len(b) <= maxPayload {
			return b, nil
		}
		resp.Truncate(maxPayload)
		b, err = resp.Pack()
		if err != nil {
			return nil, err
		}
	}
	if len(b) > maxPayload {
		return nil, fmt.Errorf("dns payload %d exceeds max %d after truncate", len(b), maxPayload)
	}
	return b, nil
}

func minimizeReply(resp *dns.Msg) {
	resp.Extra = nil
	qtype := qtypeOf(resp)
	if qtype == 0 || len(resp.Answer) == 0 {
		return
	}
	kept := make([]dns.RR, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if rr == nil {
			continue
		}
		switch rr.Header().Rrtype {
		case qtype, dns.TypeCNAME:
			kept = append(kept, rr)
		}
	}
	resp.Answer = kept
}

func qtypeOf(resp *dns.Msg) uint16 {
	if resp == nil || len(resp.Question) == 0 {
		return 0
	}
	return resp.Question[0].Qtype
}

func qtypeAnswers(resp *dns.Msg) []dns.RR {
	qtype := qtypeOf(resp)
	if qtype == 0 {
		return nil
	}
	var out []dns.RR
	for _, rr := range resp.Answer {
		if rr != nil && rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func hasQType(resp *dns.Msg, qtype uint16) bool {
	if qtype == 0 {
		return true
	}
	for _, rr := range resp.Answer {
		if rr != nil && rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}
