//go:build (linux || darwin) && !android

package log

import (
	stdlog "log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func init() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	go func() {
		buf := make([]byte, 64*1024)
		for range ch {
			n := runtime.Stack(buf, true)
			if n > 0 {
				stdlog.Printf("[ERROR] Stacktrace:\n%s", buf[:n])
			}
		}
	}()
}
