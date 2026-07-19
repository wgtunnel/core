package dns

import "github.com/miekg/dns"

type ExchangeResult struct {
	Msg          *dns.Msg
	DisableCache bool // from matched Rule
}
