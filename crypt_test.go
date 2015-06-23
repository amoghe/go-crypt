package crypt

import (
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
		t.Errorf("unexpected error: %v", err)
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
		t.Errorf("unexpected error: %t, (got %s)", err, enc)
	}

	if enc != hash {
		t.Errorf("hashed password mismatch, expected [%s] but got [%s]", hash, enc)
	}
}

func TestCryptErrors(t *testing.T) {
	tests := [][]string{
		{"no salt", ""},
		{"single char", "/"},
		{"first char bad", "!x"},
		{"second char bad", "Z%"},
		{"both chars bad", ":@"},
		{"un$upported algorithm", "$2$"},
		{"unsupported_algorithm", "_1"},
	}

	for _, test := range tests {
		enc, err := Crypt("password", test[1])
		if err == nil {
			t.Errorf("Expected error when testing %s, instead got", test[0], enc)
		}
	}
}
