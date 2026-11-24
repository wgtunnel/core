// Package instance names this install, so two variant installs on one machine
// keep their OS state apart.
package instance

import (
	"fmt"
	"regexp"
	"sync"
)

// Default is the release install's name. Its OS state predates this package, so it keeps the
// names it always had.
const Default = "wgtunnel"

var (
	mu     sync.Mutex
	name   = Default
	frozen bool
	valid  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// Set names this install. It must run before the first OS state is created, so it fails once
// Freeze has run.
func Set(n string) error {
	if !valid.MatchString(n) {
		return fmt.Errorf("invalid instance name %q", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if frozen && n != name {
		return fmt.Errorf("instance already in use as %q", name)
	}
	name = n
	return nil
}

// Freeze fixes the name, for when the first OS state that carries it is created.
func Freeze() string {
	mu.Lock()
	defer mu.Unlock()
	frozen = true
	return name
}

// Name is this install's name.
func Name() string {
	mu.Lock()
	defer mu.Unlock()
	return name
}

// IsDefault is true for the release install.
func IsDefault() bool { return Name() == Default }
