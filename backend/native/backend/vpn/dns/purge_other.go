//go:build !darwin

package dns

// PurgeSystemState has nothing to remove here. Linux and Windows set DNS on the
// tunnel interface, which goes away with it.
func PurgeSystemState() error { return nil }
