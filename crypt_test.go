package crypt

import (
	"runtime"
	"sync"
	"testing"
)

func TestCryptSHA512(t *testing.T) {
	var (
		pass = "password"
		salt = "$6$saltedsalted64$"
		hash = "$6$saltedsalted64$BG5.9QC/0aBR3V4CX82Fx1Ia244NogxWChRfDH4YyB5tjDVJd.loeTzjMWF4XTfynLPI53mEzp04eKaBaVVPp1"
	)

	enc, err := Crypt(pass, salt)
	if err != nil {
		t.Errorf("unexpected error", err)
	}

	if enc != hash {
		t.Errorf("hashed password mismatch, expected [%s], got [%s], hash, enc")
	}
}

func TestCryptMD5(t *testing.T) {
	var (
		pass = "password"
		salt = "XY"
		hash = "XYGpusIMIT/IM"
	)

	enc, err := Crypt(pass, salt)
	if err != nil {
		t.Errorf("unexpected error", err)
	}

	if enc != hash {
		t.Errorf("hashed password mismatch, expected [%s], got [%s], hash, enc")
	}
}

func TestCryptErrors(t *testing.T) {
	_, err := Crypt("weakPass", "")
	if err == nil {
		t.Error("Expected error for zero length salt")
	}

}
