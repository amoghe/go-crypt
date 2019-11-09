// +build freebsd openbsd

// Package crypt provides wrappers around functions available in crypt.h
//
// It wraps around the GNU specific extension (crypt) when the reentrant version
// (crypt_r) is unavailable. The non-reentrant version is guarded by a global lock
// so as to be safely callable from concurrent goroutines.
package crypt

import (
	"sync"
	"unsafe"
)

/*
#cgo LDFLAGS: -lcrypt
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

var (
	mu sync.Mutex
)

// Crypt provides a wrapper around the glibc crypt() function.
// For the meaning of the arguments, refer to the README.
func Crypt(pass, salt string) (string, error) {
	c_pass := C.CString(pass)
	defer C.free(unsafe.Pointer(c_pass))

	c_salt := C.CString(salt)
	defer C.free(unsafe.Pointer(c_salt))

	mu.Lock()
	c_enc, err := C.crypt(c_pass, c_salt)
	mu.Unlock()

	if c_enc == nil {
		return "", err
	}
	// returned pointer points to static data which is overwritten
	// in each call, so dont free it
	// defer C.free(unsafe.Pointer(c_enc))

	// Return nil error if the string is non-nil.
	// As per the errno.h manpage, functions are allowed to set errno
	// on success. Caller should ignore errno on success.
	return C.GoString(c_enc), err
}
