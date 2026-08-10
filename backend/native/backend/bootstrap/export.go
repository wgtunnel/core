package bootstrap

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"time"

	"github.com/wgtunnel/backend/bootstrap/bypass"
)

//export ResolveBootstrapSync
func ResolveBootstrapSync(
	host, protocol, resolvedUpstream, originalUpstream string,
	bypassFlag int32,
) *C.char {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	v4, v6, err := Resolve(ctx, host, Options{
		Protocol:         protocol,
		ResolvedUpstream: resolvedUpstream,
		OriginalUpstream: originalUpstream,
		Dialer:           bypass.Dialer(bypassFlag != 0, 0),
		Timeout:          5 * time.Second,
	})
	if err != nil {
		return C.CString("ERR|" + err.Error())
	}
	return C.CString(formatResult(v4, v6))
}