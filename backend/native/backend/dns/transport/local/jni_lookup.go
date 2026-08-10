//go:build android && cgo

package local

/*
#include <stdint.h>
#include <stdlib.h>
char* JniLookupOnUnderlayNetwork(const char* host, const char* networkFamily);
*/
import "C"

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/wgtunnel/backend/log"
)

func jniLookupOnUnderlayNetwork(ctx context.Context, network, host string) ([]netip.Addr, error) {
	log.Debug("LocalDNS", "jni fallback host=%s family=%s", host, network)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	chost := C.CString(host)
	cfam := C.CString(network)
	defer C.free(unsafe.Pointer(chost))
	defer C.free(unsafe.Pointer(cfam))

	cres := C.JniLookupOnUnderlayNetwork(chost, cfam)
	if cres == nil {
		return nil, fmt.Errorf("lookup fallback: jni failed for %s", host)
	}
	defer C.free(unsafe.Pointer(cres))

	text := strings.TrimSpace(C.GoString(cres))
	if text == "" {
		return nil, fmt.Errorf("lookup fallback: no addresses for %s", host)
	}

	var out []netip.Addr
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if addr, err := netip.ParseAddr(line); err == nil {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("lookup fallback: parse failed for %s", host)
	}
	return out, nil
}
