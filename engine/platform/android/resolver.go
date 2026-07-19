//go:build android && cgo

package android

/*
#cgo LDFLAGS: -landroid -llog

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <android/log.h>

// Attribution:
// The android_res_nsend / android_res_nresult approach is the same technique
// used by sing-box / NekoBox and several other Android networking
// projects.  These helpers below are rewritten for WG Tunnel.

typedef int (*android_res_nsend_t)(uint64_t network, const uint8_t* msg, size_t msglen, int flags);
typedef int (*android_res_nresult_t)(int fd, int* rcode, uint8_t* resp, size_t resp_len);

static void* libandroid_handle = NULL;
static android_res_nsend_t  p_android_res_nsend  = NULL;
static android_res_nresult_t p_android_res_nresult = NULL;

static int load_android_res() {
    if (libandroid_handle != NULL) {
        return (p_android_res_nsend != NULL && p_android_res_nresult != NULL) ? 0 : -1;
    }

    libandroid_handle = dlopen("libandroid.so", RTLD_NOW);
    if (!libandroid_handle) {
        return -1;
    }

    p_android_res_nsend  = (android_res_nsend_t)dlsym(libandroid_handle, "android_res_nsend");
    p_android_res_nresult = (android_res_nresult_t)dlsym(libandroid_handle, "android_res_nresult");

    if (!p_android_res_nsend || !p_android_res_nresult) {
        return -1;
    }
    return 0;
}

static int call_android_res_nsend(uint64_t network, const uint8_t* msg, size_t msglen, int flags) {
    if (load_android_res() != 0 || !p_android_res_nsend) {
        return -1;
    }
    return p_android_res_nsend(network, msg, msglen, flags);
}

static int call_android_res_nresult(int fd, int* rcode, uint8_t* resp, size_t resp_len) {
    if (!p_android_res_nresult) {
        return -1;
    }
    return p_android_res_nresult(fd, rcode, resp, resp_len);
}
*/
import "C"

import (
	"context"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/wgtunnel/core/engine/platform"
	"golang.org/x/sys/unix"
)

// Resolver implements platform.Resolver for Android.
// It prefers the raw android_res_nsend path for Android 10+ and
// falls back to the LookupFunc (network bound request) for older versions
type Resolver struct {
	// LookupFunc is a high-level fallback for older Android versions
	LookupFunc func(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error)
}

// NewResolver creates an Android resolver
func NewResolver(lookup func(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error)) *Resolver {
	return &Resolver{LookupFunc: lookup}
}

func (r *Resolver) RawExchange(ctx context.Context, networkHandle int64, request []byte) ([]byte, error) {
	if len(request) == 0 {
		return nil, fmt.Errorf("android resolver: empty request")
	}

	// Enforce a timeout
	type result struct {
		resp []byte
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		resp, err := r.rawExchange(networkHandle, request)
		ch <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.resp, res.err
	}
}

func (r *Resolver) rawExchange(networkHandle int64, request []byte) ([]byte, error) {
	msgPtr := (*C.uint8_t)(unsafe.Pointer(&request[0]))
	msgLen := C.size_t(len(request))

	fd := C.call_android_res_nsend(C.uint64_t(networkHandle), msgPtr, msgLen, 0)
	if fd < 0 {
		// Raw path not available or failed, tell the LocalTransport to fall back
		return nil, platform.ErrNotSupported
	}
	defer unix.Close(int(fd))

	// Wait for the response for 5s
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
	nReady, err := unix.Poll(pfd, 5000)
	if err != nil {
		return nil, fmt.Errorf("android resolver: poll: %w", err)
	}
	if nReady == 0 {
		return nil, context.DeadlineExceeded
	}

	buf := make([]byte, 8192)
	respPtr := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	var rcode C.int

	n := C.call_android_res_nresult(C.int(fd), &rcode, respPtr, C.size_t(len(buf)))
	if n < 0 {
		return nil, fmt.Errorf("android resolver: nresult: %s", unix.Errno(-n))
	}
	if n == 0 {
		return nil, fmt.Errorf("android resolver: empty response")
	}

	return buf[:n], nil
}

func (r *Resolver) Lookup(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error) {
	if r.LookupFunc == nil {
		return nil, platform.ErrNotSupported
	}
	return r.LookupFunc(ctx, networkHandle, network, host)
}

var _ platform.Resolver = (*Resolver)(nil)
