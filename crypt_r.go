// +build linux

// Package crypt provides wrappers around functions available in crypt.h
//
// It wraps around the GNU specific extension (crypt_r) when it is available
// (i.e. where GOOS=linux). This makes the go function reentrant (and thus
// callable from concurrent goroutines).
package crypt

import (
	"fmt"
	"unsafe"
)

/*
#cgo LDFLAGS: -lcrypt

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <crypt.h>

char *gnu_ext_crypt(char *pass, char *salt) {
  char *enc = NULL;
  char *ret = NULL;
  struct crypt_data data;
  data.initialized = 0;

  enc = crypt_r(pass, salt, &data);
  if(enc == NULL) {
    return "\0";
  }

  ret = (char *)malloc(strlen(enc)+1); // for trailing null
  strncpy(ret, enc, strlen(enc));
  ret[strlen(enc)]= '\0'; // paranoid

  return ret;
}
*/
import "C"

// Crypt provides a wrapper around the glibc crypt_r() function.
// For the meaning of the arguments, refer to the package README.
func Crypt(pass, salt string) (string, error) {
	if len(salt) < 2 {
		return "", fmt.Errorf("Invalid salt length")
	}

	c_pass := C.CString(pass)
	defer C.free(unsafe.Pointer(c_pass))

	c_salt := C.CString(salt)
	defer C.free(unsafe.Pointer(c_salt))

	c_enc := C.gnu_ext_crypt(c_pass, c_salt)
	defer C.free(unsafe.Pointer(c_enc))

	return C.GoString(c_enc), nil
}
