package handle

import "C"
import (
	"fmt"
	"math"
	"sync"
)

var (
	handleMu    sync.Mutex
	usedHandles = make(map[int32]bool)
	nextHandle  int32
)

// GenerateUniqueHandle reserves a free handle id. Caller owns it until
// ReleaseHandle, or until a successful startVpn/startProxy takes ownership
func GenerateUniqueHandle() (int32, error) {
	handleMu.Lock()
	defer handleMu.Unlock()
	for range math.MaxInt32 {
		h := nextHandle
		nextHandle++
		if nextHandle < 0 {
			nextHandle = 0
		}
		if !usedHandles[h] {
			usedHandles[h] = true
			return h, nil
		}
	}
	return -1, fmt.Errorf("no free handles available")
}

// ReleaseHandle frees a previously reserved handle. Safe to call more than once.
func ReleaseHandle(handle int32) {
	if handle < 0 {
		return
	}
	handleMu.Lock()
	delete(usedHandles, handle)
	handleMu.Unlock()
}

func IsReserved(handle int32) bool {
	if handle < 0 {
		return false
	}
	handleMu.Lock()
	defer handleMu.Unlock()
	return usedHandles[handle]
}

//export allocateTunnelHandle
func allocateTunnelHandle() int32 {
	h, err := GenerateUniqueHandle()
	if err != nil {
		return -1
	}
	return h
}

//export releaseTunnelHandle
func releaseTunnelHandle(handle int32) {
	ReleaseHandle(handle)
}
