package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxPlanJSONBytes = int64(64 << 20)

func DecodePlanJSON(encoded []byte) (Plan, error) {
	if int64(len(encoded)) > MaxPlanJSONBytes {
		return Plan{}, fmt.Errorf("cluster plan exceeds %d bytes", MaxPlanJSONBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(encoded), MaxPlanJSONBytes+1))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode cluster plan: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, errors.New("decode cluster plan: trailing JSON content")
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func EncodePlanJSON(plan Plan) ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(plan.Canonical())
}
