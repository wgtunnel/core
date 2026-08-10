package dns

// Rule is a single DNS routing rule (first match wins)
type Rule struct {
	// Domains to match to transport for empty for all
	Domains []string

	// QueryTypes IPv4, IPv6, or all types for empty
	QueryTypes []uint16

	// Transport is the registered transport tag (doh, local, plain, dot)
	Transport string

	// DisableCache disables caching of responses
	DisableCache bool
}
