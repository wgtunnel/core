package log

import "strings"

// RedactName returns a debug-log-safe version of a DNS name
func RedactName(name string) string {
	hasTrailingDot := strings.HasSuffix(name, ".")
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return name
	}

	labels := strings.Split(trimmed, ".")
	out := trimmed
	if len(labels) > 2 {
		out = "***." + strings.Join(labels[len(labels)-2:], ".")
	}
	if hasTrailingDot {
		out += "."
	}
	return out
}
