package statusnotify

/*
#cgo CFLAGS: -I${SRCDIR}/../jni/include
#include "vpn_jni.h"
*/
import "C"

import (
	"sync"
	"sync/atomic"

	"github.com/wgtunnel/backend/log"
)

const tag = "StatusNotify"

const noAck = -1

// entry tracks one tunnel. Deliveries are serialized on deliver so Kotlin applies statuses in the
// order they were sent. Kotlin acks synchronously from inside the notify call, so acked always
// reflects the last status Kotlin applied.
type entry struct {
	deliver sync.Mutex
	acked   atomic.Int32
}

var byHandle sync.Map

// Report notifies Kotlin of a new status unless Kotlin has already acked that same code.
// It is called from the packet hot path, so the unchanged case is a single atomic load.
func Report(handle int32, code int32) {
	e := getOrCreate(handle)
	if e.acked.Load() == code {
		return
	}

	// Concurrent reports (receive workers, timers, send) must not reach Kotlin out of order, or
	// the last ack can disagree with the state Kotlin ended up in and hide the next update.
	e.deliver.Lock()
	defer e.deliver.Unlock()

	acked := e.acked.Load()
	if acked == code {
		return
	}
	log.Debug(tag, "notify handle=%d code=%d acked=%d", handle, code, acked)
	notifyNow(handle, code)
}

// Ack records that Kotlin applied the status for the tunnel handle. It runs inside notifyNow on
// the delivering goroutine, so it must not take the deliver lock.
func Ack(handle int32, code int32) {
	v, ok := byHandle.Load(handle)
	if !ok {
		log.Debug(tag, "ack ignored (unknown handle=%d code=%d)", handle, code)
		return
	}
	prev := v.(*entry).acked.Swap(code)
	log.Debug(tag, "ack handle=%d code=%d (was acked=%d)", handle, code, prev)
}

// Clear drops tracking for a stopped tunnel.
func Clear(handle int32) {
	if _, ok := byHandle.LoadAndDelete(handle); ok {
		log.Debug(tag, "clear handle=%d", handle)
	}
}

// NotifyOnce sends a one-shot status without ack (for stop).
func NotifyOnce(handle int32, code int32) {
	log.Debug(tag, "notifyOnce handle=%d code=%d", handle, code)
	notifyNow(handle, code)
}

func getOrCreate(handle int32) *entry {
	if v, ok := byHandle.Load(handle); ok {
		return v.(*entry)
	}
	e := &entry{}
	e.acked.Store(noAck)
	actual, _ := byHandle.LoadOrStore(handle, e)
	return actual.(*entry)
}

func notifyNow(handle int32, code int32) {
	C.notifyStatus(C.int32_t(handle), C.int32_t(code))
}

//export ackTunnelStatus
func ackTunnelStatus(handle int32, code int32) {
	Ack(handle, code)
}
