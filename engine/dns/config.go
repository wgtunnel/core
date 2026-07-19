package dns

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TunnelDNSConfig configures WrapperTUN DNS hijacking and split DNS
// If JSON is empty, feature is off
// Upstreams are expected to be pre-resolved
// If localSuffixes is not empty registers local transport and split rules
type TunnelDNSConfig struct {
	FakeDNS          string   `json:"fakeDns"`
	DefaultTransport string   `json:"defaultTransport"` // doh, dot, plain, local
	LocalSuffixes    []string `json:"localSuffixes"`

	Upstream []string `json:"upstream"` // should be pre-resolved or empty when transport is local

	// Empty for local and plain, only for DoT and DoH SNI
	ServerName string `json:"serverName"`
}

// ParseTunnelDNSConfig parses the TunnelDNSConfig from JSON string
// Returns (nil, nil) when jsonStr is empty (feature disabled)
func ParseTunnelDNSConfig(jsonStr string) (*TunnelDNSConfig, error) {
	if strings.TrimSpace(jsonStr) == "" {
		return nil, nil
	}
	var c TunnelDNSConfig
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return nil, fmt.Errorf("dns config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *TunnelDNSConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("dns config: nil")
	}
	if strings.TrimSpace(c.FakeDNS) == "" {
		return fmt.Errorf("dns config: fakeDns is required")
	}

	switch c.DefaultTransport {
	case "doh", "dot", "plain", "local":
	case "":
		return fmt.Errorf("dns config: defaultTransport is required")
	default:
		return fmt.Errorf("dns config: invalid defaultTransport %q", c.DefaultTransport)
	}

	switch c.DefaultTransport {
	case "local":
		return nil

	case "plain":
		return requireUpstream(c.Upstream)

	case "dot":
		if strings.TrimSpace(c.ServerName) == "" {
			return fmt.Errorf("dns config: serverName is required for dot")
		}
		return requireUpstream(c.Upstream)

	case "doh":
		if strings.TrimSpace(c.ServerName) == "" {
			return fmt.Errorf("dns config: serverName is required for doh")
		}
		if err := requireUpstream(c.Upstream); err != nil {
			return err
		}
		for i, u := range c.Upstream {
			u = strings.TrimSpace(u)
			if !strings.HasPrefix(u, "https://") {
				return fmt.Errorf("dns config: upstream[%d] must be an https URL for doh", i)
			}
		}
		return nil
	}

	return nil
}

func requireUpstream(upstream []string) error {
	if len(upstream) == 0 {
		return fmt.Errorf("dns config: upstream is required")
	}
	for i, u := range upstream {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("dns config: upstream[%d] is empty", i)
		}
	}
	return nil
}
