package spec

import (
	"bytes"
	"testing"
)

func TestDesiredJSONStrictRoundTrip(t *testing.T) {
	desired := validState()
	encoded, err := EncodeDesiredJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDesiredJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := desired.Checksum()
	got, _ := decoded.Checksum()
	if got != want {
		t.Fatalf("checksum mismatch: got %s want %s", got, want)
	}
}

func TestDesiredJSONRejectsUnknownAndTrailing(t *testing.T) {
	desired := validState()
	encoded, err := EncodeDesiredJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := bytes.Replace(encoded, []byte(`"generation":1`), []byte(`"generation":1,"surprise":true`), 1)
	if _, err := DecodeDesiredJSON(withUnknown); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
	if _, err := DecodeDesiredJSON(append(encoded, []byte(` {}`)...)); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}
