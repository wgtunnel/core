//go:build !android

package local

import "sync"

// UnderlayDNS holds the current physical-interface DNS servers and ifIndex.
// It is updated by the platform network monitor.
type UnderlayDNS struct {
	mu      sync.RWMutex
	servers []string // host:port
	ifIndex uint32
}

func NewUnderlayDNS() *UnderlayDNS {
	return &UnderlayDNS{}
}

func (u *UnderlayDNS) Servers() []string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	out := make([]string, len(u.servers))
	copy(out, u.servers)
	return out
}

func (u *UnderlayDNS) IfIndex() uint32 {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.ifIndex
}

func (u *UnderlayDNS) Update(servers []string, ifIndex uint32) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.servers = servers
	u.ifIndex = ifIndex
}
