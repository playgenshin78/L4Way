package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxDesiredJSONBytes = int64(64 << 20)

func DecodeDesiredJSON(encoded []byte) (DesiredState, error) {
	if int64(len(encoded)) > MaxDesiredJSONBytes {
		return DesiredState{}, fmt.Errorf("desired state exceeds %d bytes", MaxDesiredJSONBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(encoded), MaxDesiredJSONBytes+1))
	decoder.DisallowUnknownFields()
	var desired DesiredState
	if err := decoder.Decode(&desired); err != nil {
		return DesiredState{}, fmt.Errorf("decode desired state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DesiredState{}, errors.New("decode desired state: trailing JSON content")
	}
	if err := desired.Validate(); err != nil {
		return DesiredState{}, err
	}
	return desired.Canonical(), nil
}

func EncodeDesiredJSON(desired DesiredState) ([]byte, error) {
	if err := desired.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(desired.Canonical())
	if err != nil {
		return nil, fmt.Errorf("encode desired state: %w", err)
	}
	return encoded, nil
}
