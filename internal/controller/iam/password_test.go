package iam

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("password hash contains plaintext")
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password was rejected")
	}
	if VerifyPassword(hash, "incorrect horse battery staple") {
		t.Fatal("incorrect password was accepted")
	}
	if VerifyPassword("$argon2id$invalid", "correct horse battery staple") {
		t.Fatal("malformed hash was accepted")
	}
}

func TestPasswordValidation(t *testing.T) {
	for _, password := range []string{"short", string(make([]byte, 129)), "valid-password\x00"} {
		if err := ValidatePassword(password); err == nil {
			t.Fatalf("password %q was accepted", password)
		}
	}
}
