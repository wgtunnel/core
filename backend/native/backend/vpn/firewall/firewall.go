package firewall

import "net/netip"

// Firewall is responsible for managing the system's firewall rules, especially the kill switch. It operates independently of the router.
type Firewall interface {

	// SetPersist sets whether the kill switch should persist tunnel down
	SetPersist(enabled bool)

	// SetTunnelRequirement declares which address families the currently active tunnel's
	// own config requires full-tunnel kill-switch protection for.
	SetTunnelRequirement(v4, v6 bool) error

	// SetIndependentLockdown turns the manual/persistent kill switch on (blocking both
	// families) or off. Turning it off releases a family only if the active tunnel's own
	// SetTunnelRequirement doesn't also require it.
	SetIndependentLockdown(enabled bool) error

	// IsEnabled reports whether the kill switch is currently active (any family blocked,
	// for any reason).
	IsEnabled() bool

	// IsPersistent whether the kill switch was enabled to persist tunnel changes
	IsPersistent() bool

	// Disable is a hard reset. It deactivates the kill switch unconditionally and cleans up
	// all rules and internal requirement state, ignoring any active tunnel's requirement.
	// It also removes rules an earlier process left in place.
	Disable() error

	// HasLeftoverRules reports kill switch rules an earlier process left enforced, read
	// from the OS when this firewall was created. The OS drops them on reboot.
	HasLeftoverRules() bool

	// Release leaves the current rules enforced after this process exits, for the next
	// daemon to take over without a gap. Enabling the kill switch takes leftover rules
	// over. Disable removes them. With acrossReboot, Windows also keeps them through a
	// reboot, enforced before the service starts. Elsewhere the OS drops them on reboot
	// and an early boot step puts them back.
	Release(acrossReboot bool) error

	// AllowLocalNetworks adds bypass rules for the specified local network prefixes. Requires kill switch enabled and
	// operates independently of tunnel/router bypasses.
	AllowLocalNetworks([]netip.Prefix) error

	// RemoveLocalNetworks removes any rules set by AllowLocalNetworks
	RemoveLocalNetworks() error

	IsAllowLocalNetworksEnabled() bool
}
