//go:build !android

package resume

import (
	"time"

	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/network"
	"github.com/wgtunnel/backend/util"
)

const (
	tag = "Resume"

	tick = 5 * time.Second
	// A tick this late means the machine slept
	resumeGap = 20 * time.Second
	// Radios and DHCP need a moment after wake
	settle = 5 * time.Second
	// How long to wait for a usable underlay before refreshing anyway
	underlayWait = time.Minute
)

func init() {
	go watch()
}

// watch compares wall clock time between ticks. The monotonic clock stops during
// sleep on some platforms, the wall clock does not. A clock jump of the same size
// costs one extra handshake per peer.
func watch() {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	last := time.Now().Round(0)
	for range ticker.C {
		now := time.Now().Round(0)
		gap := now.Sub(last)
		last = now
		if gap < resumeGap || len(util.LiveDevices()) == 0 {
			continue
		}
		log.Debug(tag, "Resume detected after %v", gap)
		// Wakes during the waits are covered by the rebind, a sleep after it is not
		last = refresh()
	}
}

// refresh rebinds the UDP sockets, which may not survive sleep, then starts a new
// handshake so a session the server dropped is replaced right away. It returns the
// time the rebind started.
func refresh() time.Time {
	time.Sleep(settle)
	if !awaitUnderlay() {
		// The reading may be stale. If the network is really down the handshake fails
		// and keeps retrying on its own timers.
		log.Debug(tag, "No usable network reported after resume, refreshing anyway")
	}
	started := time.Now().Round(0)
	Rebind(tag)
	return started
}

// Rebind reopens the UDP sockets of every live device and starts a new handshake on
// each, for when the underlay the sockets were using has changed.
func Rebind(logTag string) {
	for _, d := range util.LiveDevices() {
		// An inner hop device sends through the outer netstack and has no OS sockets.
		// One attempt only as a failed open resets the port, so a retry would bind a random
		// one. With no socket the handshake below fails and recovery rebuilds it.
		if d.Role != util.RoleInner {
			if err := d.Dev.BindUpdate(); err != nil {
				log.Error(logTag, "Rebind: %v", err)
			}
		}
		util.ForceHandshakes(d.Dev, logTag)
	}
}

func awaitUnderlay() bool {
	deadline := time.Now().Add(underlayWait)
	for {
		if network.GetMonitor().Current().HasUsableUnderlay() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}
