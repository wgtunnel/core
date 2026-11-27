//go:build darwin

package network

import "golang.org/x/sys/unix"

// IsRouteChange reports whether a routing socket message changes routes, addresses or
// links. Every `route get` on the system is answered with an RTM_GET broadcast to all
// routing sockets, so a watcher that reacts to those (or runs `route get` itself) never
// goes quiet.
func IsRouteChange(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}
	switch int(msg[3]) { // rt_msghdr.rtm_type
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE,
		unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO:
		return true
	}
	return false
}
