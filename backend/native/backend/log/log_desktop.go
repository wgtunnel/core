//go:build !android

package log

import (
	"fmt"
	stdlog "log"
	"os"
	"runtime"
)

func init() {
	switch runtime.GOOS {
	case "linux", "darwin":
		stdlog.SetFlags(0)
	default:
		stdlog.SetFlags(stdlog.Ldate | stdlog.Ltime | stdlog.Lmicroseconds)
	}
	stdlog.SetOutput(os.Stderr)
}

func Debug(tag, format string, args ...any) {
	if tag == "" {
		tag = "WGTunnel"
	}
	stdlog.Printf("[DEBUG] %s: %s", tag, fmt.Sprintf(format, args...))
}

func Error(tag, format string, args ...any) {
	if tag == "" {
		tag = "WGTunnel"
	}
	stdlog.Printf("[ERROR] %s: %s", tag, fmt.Sprintf(format, args...))
}
