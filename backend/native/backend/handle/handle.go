package handle

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

func ReleaseHandle(handle int32) {
	if handle < 0 {
		return
	}
	handleMu.Lock()
	delete(usedHandles, handle)
	handleMu.Unlock()
}
