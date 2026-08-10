package network

import "sync"

var (
	globalMu sync.Mutex
	global   Monitor
)

func GetMonitor() Monitor {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global == nil {
		global = NewMonitor()
	}
	return global
}

func StartMonitor() error {
	m := GetMonitor()
	return m.Start()
}
