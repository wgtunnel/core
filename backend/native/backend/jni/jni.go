package jni

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo android LDFLAGS: -llog -landroid
*/
import "C"

// Pulls in *.c in this directory into the final c-shared binary.
