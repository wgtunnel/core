//go:build !android && !linux

package bind

import "github.com/amnezia-vpn/amneziawg-go/v3/conn"

// NewBind ignores the bypass flag. Windows keeps the tunnel process out of
// its own VPN routing via a daemon-level rule
func NewBind(_ bool) conn.Bind {
	return conn.NewDefaultBind()
}
