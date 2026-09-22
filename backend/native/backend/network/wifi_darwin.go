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

const knownNetworksPlist = "/Library/Preferences/com.apple.wifi.known-networks.plist"

// currentWifiSSID infers the current Wi-Fi SSID without CoreWLAN/CoreLocation
// (both gated behind Location Services authorization on modern macOS), using
// the gateway-correlation technique from https://github.com/fjh658/get-ssid-rs.
//
// With an IPv4 gateway (the common case), filters known networks to those
// whose recorded IPv4NetworkSignature references it, then breaks ties among those candidates by recency
// With IPv6-only networks ()where there's no IPv4Router= signature to
// match at all), falls back to picking whichever known network was most recently associated
func currentWifiSSID(routerIPv4 string) string {
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

	if routerIPv4 != "" {
		return bestKnownNetworkMatch(root, "IPv4.Router="+routerIPv4, false)
	}
	return bestKnownNetworkMatch(root, "", true)
}

// bestKnownNetworkMatch scans known-network entries for the best SSID match.
// needle == "" skips the gateway-signature filter entirely (the IPv6
// fallback), in which case requireTouched must be true so an entry with no
// association timestamp at all
func bestKnownNetworkMatch(root map[string]any, needle string, requireTouched bool) string {
	var bestSSID string
	var bestAt time.Time
	found := false
	for key, v := range root {
		if !strings.HasPrefix(key, "wifi.network.ssid.") {
			continue
		}
		netEntry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if needle != "" && !matchesRouter(netEntry, needle) {
			continue
		}
		ssid := ssidFromField(netEntry["SSID"])
		if ssid == "" {
			continue
		}
		touched := lastTouched(netEntry)
		if requireTouched && touched.IsZero() {
			continue
		}
		if !found || touched.After(bestAt) {
			found = true
			bestAt = touched
			bestSSID = ssid
		}
	}
	return bestSSID
}

func matchesRouter(netEntry map[string]any, needle string) bool {
	if sig, ok := netEntry["IPv4NetworkSignature"].(string); ok && strings.Contains(sig, needle) {
		return true
	}
	bssList, ok := netEntry["BSSList"].([]any)
	if !ok {
		return false
	}
	for _, b := range bssList {
		bd, ok := b.(map[string]any)
		if !ok {
			continue
		}
		if sig, ok := bd["IPv4NetworkSignature"].(string); ok && strings.Contains(sig, needle) {
			return true
		}
	}
	return false
}

// lastTouched is the most recent join/association timestamp macOS tracks per
// known network. Requires at least one of LastAssociatedAt / JoinedByUserAt /
// JoinedBySystemAt fields specifically about this device joining - rather
// than trusting the UpdatedAt on its own, since that one could be touched by iCloud syncing.
// UpdatedAt still contributes to the max once that trust is established.
func lastTouched(netEntry map[string]any) time.Time {
	var latest time.Time
	hasAssociationSignal := false
	for _, key := range [...]string{"LastAssociatedAt", "JoinedByUserAt", "JoinedBySystemAt"} {
		if t, ok := netEntry[key].(time.Time); ok {
			hasAssociationSignal = true
			if t.After(latest) {
				latest = t
			}
		}
	}
	if !hasAssociationSignal {
		return time.Time{}
	}
	if t, ok := netEntry["UpdatedAt"].(time.Time); ok && t.After(latest) {
		latest = t
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
