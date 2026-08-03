package spec

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeHostname converts a user-facing DNS name to its canonical ASCII
// representation. Concrete IP addresses are intentionally handled by callers.
func NormalizeHostname(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", errors.New("hostname must not be empty")
	}
	value, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", errors.New("hostname is invalid")
	}
	value = strings.ToLower(value)
	if len(value) > 253 {
		return "", errors.New("hostname exceeds 253 characters")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname contains an invalid label")
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", errors.New("hostname contains an invalid character")
		}
	}
	return value, nil
}
