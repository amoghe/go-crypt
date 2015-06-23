// +build darwin freebsd netbsd

// Package crypt provides wrappers around functions available in crypt.h
//
// It wraps around the GNU specific extension (crypt) when the reentrant version
// (crypt_r) is unavailable. The non-reentrant version is guarded by a global lock
// so as to be safely callable from concurrent goroutines.
package crypt

import (
	"sync"
)

/*
#define _XOPEN_SOURCE 700
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
	c_enc := C.crypt(c_pass, c_salt)
	defer C.free(unsafe.Pointer(c_enc))
	mu.Unlock()

	return C.GoString(c_enc), nil
}
