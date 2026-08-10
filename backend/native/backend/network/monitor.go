package network

type Monitor interface {
	Current() NetworkInfo
	Notify(func(NetworkInfo))
	Start() error
	Stop()
}
