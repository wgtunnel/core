//go:build android

package bypass

/*
#include <stdint.h>
extern int bypass_socket(int fd);
*/
import "C"

import (
	"net"

	"golang.org/x/sys/unix"
)

func BypassSocket(fd uintptr) error {
	if C.bypass_socket(C.int(fd)) == 0 {
		return unix.EACCES
	}
	return nil
}

// ifIndex is ignored on Android.
func Dialer(useBypass bool, ifIndex uint32) *net.Dialer {
	_ = ifIndex
	if !useBypass {
		return &net.Dialer{}
	}
	return NewBypassDialer(BypassSocket)
}
