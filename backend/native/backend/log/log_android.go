//go:build android

package log

/*
#cgo LDFLAGS: -llog
#include <android/log.h>
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func cstring(s string) *C.char {
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		empty := [1]C.char{}
		return &empty[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func write(prio C.int, tag, msg string) {
	if tag == "" {
		tag = "WGTunnel"
	}
	const max = 3500
	if len(msg) > max {
		msg = msg[:max] + "...(truncated)"
	}
	C.__android_log_write(prio, cstring(tag), cstring(msg))
}

func Debug(tag, format string, args ...any) {
	write(C.ANDROID_LOG_DEBUG, tag, fmt.Sprintf(format, args...))
}

func Error(tag, format string, args ...any) {
	write(C.ANDROID_LOG_ERROR, tag, fmt.Sprintf(format, args...))
}

func init() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGUSR2)
	go func() {
		buf := make([]byte, 64*1024)
		for range ch {
			n := runtime.Stack(buf, true)
			if n <= 0 {
				continue
			}
			if n >= len(buf) {
				n = len(buf) - 1
			}
			write(C.ANDROID_LOG_ERROR, "AmneziaWG/Stacktrace", string(buf[:n]))
		}
	}()
}
