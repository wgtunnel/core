//go:build android

package vpn

/*
#include <stdlib.h>
int JniStrictSplitAllow(const char* network, const char* srcIp, int srcPort, const char* dstIp, int dstPort);
*/
import "C"
import "unsafe"

import "github.com/amnezia-vpn/amneziawg-go/v3/uidfilter"

// jniFilter resolves the owning app on the platform and applies the split
// policy. uidfilter calls Allow off the tun reader, from worker goroutines.
type jniFilter struct{}

func (jniFilter) Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool {
	cNetwork := C.CString(network)
	cSrc := C.CString(srcIP)
	cDst := C.CString(dstIP)
	defer C.free(unsafe.Pointer(cNetwork))
	defer C.free(unsafe.Pointer(cSrc))
	defer C.free(unsafe.Pointer(cDst))
	return C.JniStrictSplitAllow(cNetwork, cSrc, C.int(srcPort), cDst, C.int(dstPort)) != 0
}

//export applyStrictSplitFilter
func applyStrictSplitFilter(active C.int) {
	if active == 0 {
		uidfilter.Set(nil)
		return
	}
	uidfilter.Set(jniFilter{})
}
