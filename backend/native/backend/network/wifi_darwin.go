//go:build darwin

package network

import (
	"encoding/hex"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wgtunnel/backend/log"
	"howett.net/plist"
)

const (
	knownNetworksPlist = "/Library/Preferences/com.apple.wifi.known-networks.plist"

	// How fresh a known network's last-association timestamp must be to be
	// trusted as "this is the network we're on right now". Generous enough to
	// absorb our own debounce/refresh latency, tight enough that a stale
	// entry from a previous session can never win.
	associationFreshWindow = 30 * time.Second
)

// currentWifiSSID infers the current Wi-Fi SSID without CoreWLAN/CoreLocation
// (both gated behind Location Services authorization on modern macOS)
// Starting point was the gateway-correlation technique at
// https://github.com/fjh658/get-ssid-rs, but testing showed something stronger is available.
// macOS bumps UpdatedAt / LastAssociatedAt / JoinedByUserAt / JoinedBySystemAt on every association
// to a known network, even with zero config change. This is a strong signal
// rather than an trying to infer based on gateway or DHCP which
// falls apart the when two known networks share a default gateway (common
// with 192.168.1.1 style addresses). Since only one network can be associated
// at a time, picking whichever known network was most recently touched, gated
// by associationFreshWindow so a stale entry can never win, sidesteps the
// gateway collision problem entirely rather than just scoring around it.
func currentWifiSSID(now time.Time) string {
	data, err := os.ReadFile(knownNetworksPlist)
	if err != nil {
		log.Debug(tag, "read known-networks plist: %v", err)
		return ""
	}

	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		log.Debug(tag, "decode known-networks plist: %v", err)
		return ""
	}

	var bestSSID string
	var bestAt time.Time
	for key, v := range root {
		if !strings.HasPrefix(key, "wifi.network.ssid.") {
			continue
		}
		netEntry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		touched := lastTouched(netEntry)
		if touched.IsZero() || touched.After(now) || now.Sub(touched) > associationFreshWindow {
			continue
		}
		if !touched.After(bestAt) {
			continue
		}
		ssid := ssidFromField(netEntry["SSID"])
		if ssid == "" {
			continue
		}
		bestAt = touched
		bestSSID = ssid
	}
	return bestSSID
}

// lastTouched is the most recent of every join/association timestamp macOS
// tracks per known network. Which specific field moves depends on how the
// rejoin or join happened (user-initiated vs system rejoin, like after a
// radio power cycle), so all four are checked rather than relying on one.
func lastTouched(netEntry map[string]any) time.Time {
	var latest time.Time
	for _, key := range [...]string{"UpdatedAt", "LastAssociatedAt", "JoinedByUserAt", "JoinedBySystemAt"} {
		if t, ok := netEntry[key].(time.Time); ok && t.After(latest) {
			latest = t
		}
	}
	return latest
}

// SSID is usually a plist string, but macOS stores it as raw bytes (data)
// for SSIDs that aren't valid UTF-8.
func ssidFromField(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		if utf8.Valid(val) {
			return string(val)
		}
		return hex.EncodeToString(val)
	default:
		return ""
	}
}
