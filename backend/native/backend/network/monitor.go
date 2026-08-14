package network

import "errors"

// TUN owns the default route; keep the last physical underlay
var errPhysicalDefaultHidden = errors.New("physical default hidden by tunnel")

type Monitor interface {
	Current() NetworkInfo
	Notify(func(NetworkInfo))
	Start() error
	Stop()
}
