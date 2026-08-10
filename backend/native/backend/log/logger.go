package log

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

type Logger struct {
	tag string
}

func WithTag(tag string) *Logger {
	if tag == "" {
		tag = "WGTunnel"
	}
	return &Logger{tag: tag}
}

func (l *Logger) Debug(format string, args ...any) {
	if l == nil {
		Debug("WGTunnel", format, args...)
		return
	}
	Debug(l.tag, format, args...)
}

func (l *Logger) Error(format string, args ...any) {
	if l == nil {
		Error("WGTunnel", format, args...)
		return
	}
	Error(l.tag, format, args...)
}

// Child appends a suffix
func (l *Logger) Child(suffix string) *Logger {
	base := "WGTunnel"
	if l != nil && l.tag != "" {
		base = l.tag
	}
	if suffix == "" {
		return WithTag(base)
	}
	return WithTag(base + "/" + suffix)
}

func (l *Logger) Tag() string {
	if l == nil || l.tag == "" {
		return "WGTunnel"
	}
	return l.tag
}

func (l *Logger) DeviceLogger() *device.Logger {
	tag := l.Tag()
	return &device.Logger{
		Verbosef: func(format string, args ...any) { Debug(tag, format, args...) },
		Errorf:   func(format string, args ...any) { Error(tag, format, args...) },
	}
}
