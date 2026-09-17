package network

type NetworkType int

// Mirror Android defaults for consistency
const (
	UnknownSSID  = "unknown_ssid"
	UnknownBSSID = "02:00:00:00:00:00"
)

const (
	NetworkDisconnected NetworkType = iota
	NetworkWifi
	NetworkEthernet
	NetworkOther
)

type NetworkInfo struct {
	Type          NetworkType
	InterfaceName string
	IfIndex       uint32

	// Wi-Fi only
	SSID  string
	BSSID string

	HasIPv4 bool
	HasIPv6 bool

	DNSServers []string
}

func (n NetworkInfo) HasUsableUnderlay() bool {
	return n.Type != NetworkDisconnected && n.IfIndex != 0
}

func (n NetworkInfo) IsWifi() bool {
	return n.Type == NetworkWifi
}

func (n NetworkInfo) HasKnownSSID() bool {
	return n.IsWifi() && n.SSID != "" && n.SSID != UnknownSSID
}

func (n NetworkInfo) HasKnownBSSID() bool {
	return n.IsWifi() && n.BSSID != "" && n.BSSID != UnknownBSSID
}

func (a NetworkInfo) Equal(b NetworkInfo) bool {
	if a.Type != b.Type ||
		a.InterfaceName != b.InterfaceName ||
		a.IfIndex != b.IfIndex ||
		a.SSID != b.SSID ||
		a.BSSID != b.BSSID ||
		a.HasIPv4 != b.HasIPv4 ||
		a.HasIPv6 != b.HasIPv6 {
		return false
	}
	if len(a.DNSServers) != len(b.DNSServers) {
		return false
	}
	for i := range a.DNSServers {
		if a.DNSServers[i] != b.DNSServers[i] {
			return false
		}
	}
	return true
}
