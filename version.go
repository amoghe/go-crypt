// +build linux

package crypt

/*
#include <gnu/libc-version.h>
*/
import "C"

// Returns version string from libc
func libCVersion() string {
	c_ver := C.gnu_get_libc_version()
	return C.GoString(c_ver)
}
