package transport

import "regexp"

var urlCredentials = regexp.MustCompile(`://([^/?#@\s"',]*?):([^/?#@\s"',]*)@`)

// RedactCredentials masks the password of every user:password@ URL
func RedactCredentials(s string) string {
	return urlCredentials.ReplaceAllString(s, "://$1:***@")
}
