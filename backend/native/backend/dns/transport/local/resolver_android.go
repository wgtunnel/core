//go:build android && cgo

package local

/*
#cgo LDFLAGS: -landroid -llog

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <android/log.h>
#include <pthread.h>

// Attribution:
// The android_res_nsend / android_res_nresult approach is the same technique
// used by sing-box / NekoBox and several other Android networking
// projects.  These helpers below are rewritten for WG Tunnel.

typedef int (*android_res_nsend_t)(uint64_t network, const uint8_t* msg, size_t msglen, int flags);
typedef int (*android_res_nresult_t)(int fd, int* rcode, uint8_t* resp, size_t resp_len);
typedef void (*android_res_cancel_t)(int nsend_fd);

static android_res_nsend_t   p_android_res_nsend   = NULL;
static android_res_nresult_t p_android_res_nresult = NULL;
static android_res_cancel_t  p_android_res_cancel  = NULL;
static pthread_once_t android_res_once = PTHREAD_ONCE_INIT;

// Runs once, so concurrent first lookups never see a half loaded set of functions
static void load_android_res_once(void) {
    void* handle = dlopen("libandroid.so", RTLD_NOW);
    if (!handle) {
        return;
    }
    android_res_nsend_t nsend = (android_res_nsend_t)dlsym(handle, "android_res_nsend");
    android_res_nresult_t nresult = (android_res_nresult_t)dlsym(handle, "android_res_nresult");
    android_res_cancel_t cancel = (android_res_cancel_t)dlsym(handle, "android_res_cancel");
    if (!nsend || !nresult || !cancel) {
        return;
    }
    p_android_res_nresult = nresult;
    p_android_res_cancel = cancel;
    p_android_res_nsend = nsend;
}

static int call_android_res_nsend(uint64_t network, const uint8_t* msg, size_t msglen, int flags) {
    pthread_once(&android_res_once, load_android_res_once);
    if (!p_android_res_nsend) {
        return -1;
    }
    return p_android_res_nsend(network, msg, msglen, flags);
}

// Reads the answer and closes fd, whatever the result
static int call_android_res_nresult(int fd, int* rcode, uint8_t* resp, size_t resp_len) {
    return p_android_res_nresult(fd, rcode, resp, resp_len);
}

// Abandons the query and closes fd
static void call_android_res_cancel(int fd) {
    p_android_res_cancel(fd);
}
*/
import "C"

import (
	"context"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Resolver implements platform.Resolver for Android.
// It prefers the raw android_res_nsend path for Android 10+ and
// falls back to the LookupFunc (network bound request) for older versions
type androidResolver struct {
	LookupFunc func(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error)
}

// NewResolver creates an Android resolver
func NewResolver(lookup func(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error)) Resolver {
	return &androidResolver{LookupFunc: lookup}
}

func (r *androidResolver) RawExchange(ctx context.Context, networkHandle int64, request []byte) ([]byte, error) {
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

func (r *androidResolver) rawExchange(networkHandle int64, request []byte) ([]byte, error) {
	if networkHandle == 0 {
		return nil, fmt.Errorf("android local: no underlay network handle")
	}
	msgPtr := (*C.uint8_t)(unsafe.Pointer(&request[0]))
	msgLen := C.size_t(len(request))

	fd := C.call_android_res_nsend(C.uint64_t(networkHandle), msgPtr, msgLen, 0)
	if fd < 0 {
		// Raw path not available or failed, tell the LocalTransport to fall back
		return nil, ErrNotSupported
	}
	// The fd belongs to the platform resolver: android_res_nresult closes it after reading, and
	// android_res_cancel closes it when the answer is abandoned. Closing it here as well would
	// close whatever reused the number since, which fdsan then aborts on.

	// Wait for the response for 5s. Go interrupts its threads with signals, so a poll that returns
	// EINTR is retried with the time left rather than failing the query.
	deadline := time.Now().Add(5 * time.Second)
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			C.call_android_res_cancel(fd)
			return nil, context.DeadlineExceeded
		}
		nReady, err := unix.Poll(pfd, int(remaining.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			C.call_android_res_cancel(fd)
			return nil, fmt.Errorf("android resolver: poll: %w", err)
		}
		if nReady == 0 {
			C.call_android_res_cancel(fd)
			return nil, context.DeadlineExceeded
		}
		break
	}

	buf := make([]byte, 8192)
	respPtr := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	var rcode C.int

	n := C.call_android_res_nresult(C.int(fd), &rcode, respPtr, C.size_t(len(buf)))
	if n < 0 {
		return nil, fmt.Errorf("android resolver: result: %s", unix.Errno(-n))
	}
	if n == 0 {
		return nil, fmt.Errorf("android resolver: empty response")
	}

	return buf[:n], nil
}

func (r *androidResolver) Lookup(ctx context.Context, networkHandle int64, network, host string) ([]netip.Addr, error) {
	if r.LookupFunc == nil {
		return nil, ErrNotSupported
	}
	return r.LookupFunc(ctx, networkHandle, network, host)
}

var _ Resolver = (*androidResolver)(nil)
