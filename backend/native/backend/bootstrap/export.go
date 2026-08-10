package bootstrap

/*
#include <stdint.h>
#include <stdlib.h>
extern void NotifyDnsResult(int64_t id, const char* result);
*/
import "C"

import (
	"context"
	"time"
	"unsafe"

	"github.com/wgtunnel/backend/bootstrap/bypass"
)

//export StartResolveBootstrap
func StartResolveBootstrap(
	id int64,
	host, protocol, resolvedUpstream, originalUpstream string,
	bypass int32,
) {
	go startResolveBootstrap(
		id,
		host,
		protocol,
		resolvedUpstream,
		originalUpstream,
		bypass,
		0,
	)
}

func startResolveBootstrap(
	id int64,
	host, protocol, resolved, original string,
	bypassFlag int32,
	physicalIfIndex uint32,
) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		v4, v6, err := Resolve(ctx, host, Options{
			Protocol:         protocol,
			ResolvedUpstream: resolved,
			OriginalUpstream: original,
			Dialer:           bypass.Dialer(bypassFlag != 0, physicalIfIndex),
			Timeout:          5 * time.Second,
		})
		if err != nil {
			notifyResult(id, "ERR|"+err.Error())
			return
		}
		notifyResult(id, formatResult(v4, v6))
	}()
}

func notifyResult(id int64, result string) {
	c := C.CString(result)
	defer C.free(unsafe.Pointer(c))
	C.NotifyDnsResult(C.int64_t(id), c)
}
