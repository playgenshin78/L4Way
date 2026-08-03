//go:build !linux

package conntrack

import (
	"context"
	"errors"

	"flux.local/flux/internal/spec"
)

var ErrUnsupportedPlatform = errors.New("conntrack cleanup is only supported on Linux")

type Cleaner struct{}

func NewCleaner() *Cleaner { return &Cleaner{} }

func (*Cleaner) Delete(_ context.Context, _ string, forwards []spec.ForwardSpec) (uint, error) {
	if len(forwards) == 0 {
		return 0, nil
	}
	return 0, ErrUnsupportedPlatform
}
