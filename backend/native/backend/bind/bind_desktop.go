//go:build !android && !linux

package bind

import "github.com/amnezia-vpn/amneziawg-go/v3/conn"

func NewBind() conn.Bind {
	return conn.NewDefaultBind()
}
