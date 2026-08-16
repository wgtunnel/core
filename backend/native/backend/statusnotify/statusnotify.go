package statusnotify

/*
#cgo CFLAGS: -I${SRCDIR}/../jni/include
#include "vpn_jni.h"
*/
import "C"

import (
	"sync"

	"github.com/wgtunnel/backend/log"
)

const tag = "StatusNotify"

type entry struct {
	mu     sync.Mutex
	acked  int32
	hasAck bool
}

var byHandle sync.Map

// Report notifies Kotlin of a new status unless Kotlin has already acked that same code.
func Report(handle int32, code int32) {
	e := getOrCreate(handle)
	e.mu.Lock()
	skip := e.hasAck && e.acked == code
	acked := e.acked
	hasAck := e.hasAck
	e.mu.Unlock()
	if skip {
		return
	}
	log.Debug(tag, "notify handle=%d code=%d acked=%d hasAck=%v", handle, code, acked, hasAck)
	notifyNow(handle, code)
}

// Ack records that Kotlin applied the status for the tunnel handle.
func Ack(handle int32, code int32) {
	v, ok := byHandle.Load(handle)
	if !ok {
		log.Debug(tag, "ack ignored (unknown handle=%d code=%d)", handle, code)
		return
	}
	e := v.(*entry)
	e.mu.Lock()
	prev := e.acked
	had := e.hasAck
	e.acked = code
	e.hasAck = true
	e.mu.Unlock()
	log.Debug(tag, "ack handle=%d code=%d (was acked=%d hasAck=%v)", handle, code, prev, had)
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
