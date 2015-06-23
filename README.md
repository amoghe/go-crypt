go-crypt (`crypt`)
==================

Package `crypt` provides go language wrappers around crypt(3). For further information on crypt see the
[man page](http://man7.org/linux/man-pages/man3/crypt.3.html)

If you have questions about how to use crypt (the C function), it is likely this is not the package you
are looking for.

Example
-------
```go
import (
	"fmt"
	"github.com/amoghe/go-crypt"
)

func main() {
	md5, err := crypt.Crypt("password", "in")
	if err != nil {
		fmt.Errorf("error:", err)
		return
	}

	sha512, err := crypt.Crypt("password", "$6$SomeSaltSomePepper$")
	if err != nil {
		fmt.Errorf("error:", err)
		return
	}

	fmt.Println("MD5:", md5)
	fmt.Println("SHA512:", sha512)
}
```

A Note On "Salt"
----------------

You can find out more about salt [here](https://en.wikipedia.org/wiki/Salt_(cryptography))

The hash algorithm can be selected via the salt string. Here is how to do it (relevant
section from the man page):

```
   If salt is a character string starting with the characters
   "$id$" followed by a string terminated by "$":

       $id$salt$encrypted

   then instead of using the DES machine, id identifies the
   encryption method used and this then determines how the rest
   of the password string is interpreted.  The following values
   of id are supported:

          ID  | Method
          ─────────────────────────────────────────────────────────
          1   | MD5
          2a  | Blowfish (not in mainline glibc; added in some
              | Linux distributions)
          5   | SHA-256 (since glibc 2.7)
          6   | SHA-512 (since glibc 2.7)

   So $5$salt$encrypted is an SHA-256 encoded password and
   $6$salt$encrypted is an SHA-512 encoded one.

   "salt" stands for the up to 16 characters following "$id$" in
   the salt.  The encrypted part of the password string is the
   actual computed password.  The size of this string is fixed:

   MD5     | 22 characters
   SHA-256 | 43 characters
   SHA-512 | 86 characters
```

Platforms
---------

This package has been tested on ubuntu 14.04 which ships with libc6. Additionally, this package assumes
that on GOOS=linux the GNU extensions to crypt are available and therefore reentrant versions of the
crypt function (`crypt_r`) is available, and attempts to use that instead.

On other platforms (freebsd, netbsd) it makes no such assumptions and will wrap around the plain crypt
function instead (providing serialized access to it).

Unfortunately, I do not have access to machines that run anything other than Ubuntu, hence the other
platforms have not been tested, however I believe they should work just fine. If you can verify this
(or provide a patch that fixes this), I would be grateful.

TODO
----

* Gather errno from C land.
* Find someone with access to *BSD system(s)

License
-------

Released under the [MIT License](LICENSE)