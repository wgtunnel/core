package log

type Logger struct {
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

func Nop() *Logger {
	return &Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	}
}
