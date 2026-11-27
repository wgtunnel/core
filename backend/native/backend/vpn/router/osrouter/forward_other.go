//go:build !darwin

package osrouter

// PurgeForwarding has nothing to drop here: only macOS loads forwarding rules for a tunnel.
func PurgeForwarding() {}
