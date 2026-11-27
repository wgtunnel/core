//go:build darwin

package network

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// IsRouteChange reports whether a routing socket message changes routes, addresses or
// links. Every `route get` on the system is answered with an RTM_GET broadcast to all
// routing sockets, so a watcher that reacts to those (or runs `route get` itself) never
// goes quiet. The reply to a failed request is broadcast too, with rtm_errno set, and
// changed nothing: a watcher re-adding a route that already exists would wake itself.
func IsRouteChange(msg []byte) bool {
	if len(msg) < unix.SizeofRtMsghdr {
		return false
	}
	hdr := (*unix.RtMsghdr)(unsafe.Pointer(&msg[0]))
	if hdr.Errno != 0 {
		return false
	}
	switch int(hdr.Type) {
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE,
		unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO:
		return true
	}
	return false
}
