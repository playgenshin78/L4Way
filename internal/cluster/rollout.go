package cluster

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"

	"flux.local/flux/internal/spec"
)

var ErrUnsafeRollout = errors.New("cluster rollout cannot preserve the active path")

type RolloutWave string

const (
	RolloutWaveCanary       RolloutWave = "canary"
	RolloutWaveFull         RolloutWave = "full"
	RolloutWaveCompensation RolloutWave = "compensation"
)

type RolloutPhase string

const (
	RolloutPhasePrepare    RolloutPhase = "prepare"
	RolloutPhasePromote    RolloutPhase = "promote"
	RolloutPhaseCleanup    RolloutPhase = "cleanup"
	RolloutPhaseBake       RolloutPhase = "bake"
	RolloutPhaseCompensate RolloutPhase = "compensate"
)

// RolloutStage is a complete per-node snapshot barrier. Desired contains only
// nodes whose semantic state changes at this barrier. A bake stage has no
// Desired targets and is advanced by the Controller clock.
type RolloutStage struct {
	Wave        RolloutWave
	Phase       RolloutPhase
	BakeSeconds uint32
	Desired     map[string]spec.DesiredState
}

// BuildRolloutStages produces an exit-first publication sequence. Current is
// the last desired state published to every involved node; target is the final
// scheduler output. Every returned snapshot is independently valid, allowing
// it to be persisted and resumed after a Controller restart.
func BuildRolloutStages(planID string, strategy RolloutStrategy, current, target map[string]spec.DesiredState) ([]RolloutStage, []string, error) {
	working := completeStateMap(current, target)
	final := completeStateMap(target, current)
	if err := validateFabricTransitions(working, final); err != nil {
		return nil, nil, err
	}
	if err := validateRoleTransitions(working, final); err != nil {
		return nil, nil, err
	}

	changedForwards := changedForwardIDs(working, final)
	if len(changedForwards) == 0 {
		desired := changedStates(working, final)
		if len(desired) == 0 {
			return nil, nil, nil
		}
		return []RolloutStage{{Wave: RolloutWaveFull, Phase: RolloutPhasePromote, Desired: desired}}, nil, nil
	}

	canary, remainder := selectCanary(planID, changedForwards, strategy.EffectiveCanaryPercent())
	stages := make([]RolloutStage, 0, 7)
	if len(canary) != 0 && len(remainder) != 0 {
		var err error
		working, stages, err = appendWaveStages(working, final, canary, RolloutWaveCanary, false, stages)
		if err != nil {
			return nil, nil, err
		}
		stages = append(stages, RolloutStage{Wave: RolloutWaveCanary, Phase: RolloutPhaseBake, BakeSeconds: strategy.BakeSeconds})
		working, stages, err = appendWaveStages(working, final, remainder, RolloutWaveFull, true, stages)
		if err != nil {
			return nil, nil, err
		}
		return stages, canary, nil
	}

	var err error
	working, stages, err = appendWaveStages(working, final, changedForwards, RolloutWaveFull, true, stages)
	if err != nil {
		return nil, nil, err
	}
	return stages, nil, nil
}

func appendWaveStages(working, final map[string]spec.DesiredState, selected []string, wave RolloutWave, exactFinal bool, stages []RolloutStage) (map[string]spec.DesiredState, []RolloutStage, error) {
	selectedSet := make(map[string]struct{}, len(selected))
	for _, forwardID := range selected {
		selectedSet[forwardID] = struct{}{}
	}
	currentIndex := indexForwards(working)
	finalIndex := indexForwards(final)

	apply := func(phase RolloutPhase, mutate func(map[string]spec.DesiredState)) error {
		next := cloneStateMap(working)
		mutate(next)
		if phase == RolloutPhaseCleanup && exactFinal {
			next = cloneStateMap(final)
		}
		desired := changedStates(working, next)
		for nodeID, state := range desired {
			if err := state.Validate(); err != nil {
				return fmt.Errorf("%w: %s/%s target for node %s is invalid: %v", ErrUnsafeRollout, wave, phase, nodeID, err)
			}
		}
		working = next
		if len(desired) != 0 {
			stages = append(stages, RolloutStage{Wave: wave, Phase: phase, Desired: desired})
		}
		return nil
	}

	if err := apply(RolloutPhasePrepare, func(next map[string]spec.DesiredState) {
		for forwardID := range selectedSet {
			for nodeID, forward := range finalIndex[forwardID] {
				if forward.PathMode != spec.PathViaExit || nodeID != forward.ExitNodeID {
					continue
				}
				state := withConservativeResources(next[nodeID], final[nodeID])
				state.Forwards = upsertForward(state.Forwards, forward)
				next[nodeID] = canonicalStageState(state, nodeID)
			}
		}
	}); err != nil {
		return nil, nil, err
	}

	if err := apply(RolloutPhasePromote, func(next map[string]spec.DesiredState) {
		for forwardID := range selectedSet {
			for nodeID, forward := range currentIndex[forwardID] {
				if nodeID != forward.IngressNodeID {
					continue
				}
				state := withConservativeResources(next[nodeID], final[nodeID])
				state.Forwards = removeForward(state.Forwards, forwardID)
				next[nodeID] = canonicalStageState(state, nodeID)
			}
			for nodeID, forward := range finalIndex[forwardID] {
				if nodeID != forward.IngressNodeID {
					continue
				}
				state := withConservativeResources(next[nodeID], final[nodeID])
				state.Forwards = upsertForward(state.Forwards, forward)
				next[nodeID] = canonicalStageState(state, nodeID)
			}
		}
	}); err != nil {
		return nil, nil, err
	}

	if err := apply(RolloutPhaseCleanup, func(next map[string]spec.DesiredState) {
		for forwardID := range selectedSet {
			for nodeID, forward := range currentIndex[forwardID] {
				if forward.PathMode != spec.PathViaExit || nodeID != forward.ExitNodeID {
					continue
				}
				state := withConservativeResources(next[nodeID], final[nodeID])
				state.Forwards = removeForward(state.Forwards, forwardID)
				next[nodeID] = canonicalStageState(state, nodeID)
			}
			for nodeID, forward := range finalIndex[forwardID] {
				if forward.PathMode != spec.PathViaExit || nodeID != forward.ExitNodeID {
					continue
				}
				state := withConservativeResources(next[nodeID], final[nodeID])
				state.Forwards = upsertForward(state.Forwards, forward)
				next[nodeID] = canonicalStageState(state, nodeID)
			}
		}
	}); err != nil {
		return nil, nil, err
	}
	return working, stages, nil
}

func completeStateMap(primary, secondary map[string]spec.DesiredState) map[string]spec.DesiredState {
	result := make(map[string]spec.DesiredState, len(primary)+len(secondary))
	for nodeID := range secondary {
		result[nodeID] = emptyStageState(nodeID)
	}
	for nodeID, state := range primary {
		result[nodeID] = canonicalStageState(state, nodeID)
	}
	return result
}

func cloneStateMap(source map[string]spec.DesiredState) map[string]spec.DesiredState {
	result := make(map[string]spec.DesiredState, len(source))
	for nodeID, state := range source {
		result[nodeID] = canonicalStageState(state, nodeID)
	}
	return result
}

func emptyStageState(nodeID string) spec.DesiredState {
	return spec.DesiredState{SchemaVersion: spec.CurrentSchemaVersion, NodeID: nodeID, Generation: 1}
}

func canonicalStageState(state spec.DesiredState, nodeID string) spec.DesiredState {
	state.NodeID = nodeID
	state.Generation = 1
	if state.SchemaVersion == 0 {
		state.SchemaVersion = spec.CurrentSchemaVersion
	}
	return state.Canonical()
}

func changedStates(current, next map[string]spec.DesiredState) map[string]spec.DesiredState {
	result := make(map[string]spec.DesiredState)
	nodeIDs := make(map[string]struct{}, len(current)+len(next))
	for nodeID := range current {
		nodeIDs[nodeID] = struct{}{}
	}
	for nodeID := range next {
		nodeIDs[nodeID] = struct{}{}
	}
	for nodeID := range nodeIDs {
		left := current[nodeID]
		right, exists := next[nodeID]
		if !exists {
			right = emptyStageState(nodeID)
		}
		if !desiredStatesEqual(left, right) {
			result[nodeID] = canonicalStageState(right, nodeID)
		}
	}
	return result
}

func desiredStatesEqual(left, right spec.DesiredState) bool {
	normalize := func(state spec.DesiredState) spec.DesiredState {
		state = canonicalStageState(state, state.NodeID)
		for index := range state.UserPolicies {
			state.UserPolicies[index].TrafficClassID = 0
		}
		for index := range state.Forwards {
			state.Forwards[index].TrafficClassID = 0
		}
		return state
	}
	return reflect.DeepEqual(normalize(left), normalize(right))
}

func indexForwards(states map[string]spec.DesiredState) map[string]map[string]spec.ForwardSpec {
	result := make(map[string]map[string]spec.ForwardSpec)
	for nodeID, state := range states {
		for _, forward := range state.Forwards {
			if result[forward.ID] == nil {
				result[forward.ID] = make(map[string]spec.ForwardSpec)
			}
			result[forward.ID][nodeID] = forward
		}
	}
	return result
}

func changedForwardIDs(current, final map[string]spec.DesiredState) []string {
	left := indexForwards(current)
	right := indexForwards(final)
	ids := make(map[string]struct{}, len(left)+len(right))
	for forwardID := range left {
		ids[forwardID] = struct{}{}
	}
	for forwardID := range right {
		ids[forwardID] = struct{}{}
	}
	result := make([]string, 0, len(ids))
	for forwardID := range ids {
		if !forwardLocationsEqual(left[forwardID], right[forwardID]) {
			result = append(result, forwardID)
		}
	}
	sort.Strings(result)
	return result
}

func forwardLocationsEqual(left, right map[string]spec.ForwardSpec) bool {
	if len(left) != len(right) {
		return false
	}
	for nodeID, first := range left {
		second, exists := right[nodeID]
		if !exists {
			return false
		}
		first.TrafficClassID = 0
		second.TrafficClassID = 0
		if !reflect.DeepEqual(first, second) {
			return false
		}
	}
	return true
}

func upsertForward(forwards []spec.ForwardSpec, target spec.ForwardSpec) []spec.ForwardSpec {
	result := make([]spec.ForwardSpec, 0, len(forwards)+1)
	replaced := false
	for _, forward := range forwards {
		if forward.ID == target.ID {
			if !replaced {
				result = append(result, target)
				replaced = true
			}
			continue
		}
		result = append(result, forward)
	}
	if !replaced {
		result = append(result, target)
	}
	return result
}

func removeForward(forwards []spec.ForwardSpec, forwardID string) []spec.ForwardSpec {
	result := make([]spec.ForwardSpec, 0, len(forwards))
	for _, forward := range forwards {
		if forward.ID != forwardID {
			result = append(result, forward)
		}
	}
	return result
}

func withConservativeResources(state, final spec.DesiredState) spec.DesiredState {
	if final.SchemaVersion > state.SchemaVersion {
		state.SchemaVersion = final.SchemaVersion
	}
	if state.SchemaVersion == 0 {
		state.SchemaVersion = spec.CurrentSchemaVersion
	}
	if state.ManagementDomain == "" {
		state.ManagementDomain = final.ManagementDomain
	}

	state.ServiceCIDRs = mergeServiceCIDRs(state.ServiceCIDRs, final.ServiceCIDRs)
	state.FabricLinks = mergeFabricLinks(state.FabricLinks, final.FabricLinks)
	state.HealthChecks = mergeHealthChecks(state.HealthChecks, final.HealthChecks)
	state.UserPolicies = mergeUserPolicies(state.UserPolicies, final.UserPolicies)
	if final.ProtocolBlocks != nil && final.ProtocolBlocks.Any() {
		policy := *final.ProtocolBlocks
		state.ProtocolBlocks = &policy
	} else {
		state.ProtocolBlocks = nil
	}
	return state.Canonical()
}

func mergeServiceCIDRs(current, final []netip.Prefix) []netip.Prefix {
	merged := make(map[string]netip.Prefix, len(current)+len(final))
	for _, prefix := range current {
		merged[prefix.Masked().String()] = prefix.Masked()
	}
	for _, prefix := range final {
		merged[prefix.Masked().String()] = prefix.Masked()
	}
	result := make([]netip.Prefix, 0, len(merged))
	for _, prefix := range merged {
		result = append(result, prefix)
	}
	return result
}

func mergeFabricLinks(current, final []spec.FabricLinkSpec) []spec.FabricLinkSpec {
	merged := make(map[string]spec.FabricLinkSpec, len(current)+len(final))
	for _, link := range current {
		merged[link.ID] = link
	}
	for _, link := range final {
		merged[link.ID] = link
	}
	result := make([]spec.FabricLinkSpec, 0, len(merged))
	for _, link := range merged {
		result = append(result, link)
	}
	return result
}

func mergeHealthChecks(current, final []spec.HealthCheckSpec) []spec.HealthCheckSpec {
	key := func(check spec.HealthCheckSpec) string { return check.PoolID + "\x00" + check.BackendID }
	merged := make(map[string]spec.HealthCheckSpec, len(current)+len(final))
	for _, check := range current {
		merged[key(check)] = check
	}
	for _, check := range final {
		merged[key(check)] = check
	}
	result := make([]spec.HealthCheckSpec, 0, len(merged))
	for _, check := range merged {
		result = append(result, check)
	}
	return result
}

func mergeUserPolicies(current, final []spec.UserPolicySpec) []spec.UserPolicySpec {
	merged := make(map[string]spec.UserPolicySpec, len(current)+len(final))
	for _, policy := range current {
		merged[policy.UserID] = policy
	}
	for _, policy := range final {
		merged[policy.UserID] = policy
	}
	result := make([]spec.UserPolicySpec, 0, len(merged))
	for _, policy := range merged {
		result = append(result, policy)
	}
	return result
}

func validateRoleTransitions(current, final map[string]spec.DesiredState) error {
	left := indexForwards(current)
	right := indexForwards(final)
	for forwardID, currentNodes := range left {
		finalNodes := right[forwardID]
		for nodeID, before := range currentNodes {
			after, exists := finalNodes[nodeID]
			if exists && forwardNodeRole(before, nodeID) != forwardNodeRole(after, nodeID) {
				return fmt.Errorf("%w: forward %s changes node %s from %s to %s; use an intermediate placement", ErrUnsafeRollout, forwardID, nodeID, forwardNodeRole(before, nodeID), forwardNodeRole(after, nodeID))
			}
		}
		beforeIngress, beforeExit, beforeVia := placementFromLocations(currentNodes)
		afterIngress, afterExit, afterVia := placementFromLocations(finalNodes)
		if beforeVia && afterVia && beforeExit == afterExit && beforeIngress != afterIngress {
			return fmt.Errorf("%w: forward %s changes ingress while retaining exit %s; move through a different exit first", ErrUnsafeRollout, forwardID, beforeExit)
		}
	}
	return nil
}

func forwardNodeRole(forward spec.ForwardSpec, nodeID string) string {
	if nodeID == forward.IngressNodeID {
		return "ingress"
	}
	if forward.PathMode == spec.PathViaExit && nodeID == forward.ExitNodeID {
		return "exit"
	}
	return "unassigned"
}

func placementFromLocations(locations map[string]spec.ForwardSpec) (string, string, bool) {
	for _, forward := range locations {
		return forward.IngressNodeID, forward.ExitNodeID, forward.PathMode == spec.PathViaExit
	}
	return "", "", false
}

func validateFabricTransitions(current, final map[string]spec.DesiredState) error {
	for nodeID, before := range current {
		after := final[nodeID]
		used := make(map[string]struct{}, len(before.Forwards)+len(after.Forwards))
		for _, forward := range before.Forwards {
			if forward.FabricLinkID != "" {
				used[forward.FabricLinkID] = struct{}{}
			}
		}
		for _, forward := range after.Forwards {
			if forward.FabricLinkID != "" {
				used[forward.FabricLinkID] = struct{}{}
			}
		}
		beforeLinks := make(map[string]spec.FabricLinkSpec, len(before.FabricLinks))
		for _, link := range before.FabricLinks {
			beforeLinks[link.ID] = link
		}
		for _, link := range after.FabricLinks {
			previous, exists := beforeLinks[link.ID]
			if !exists || reflect.DeepEqual(previous, link) {
				continue
			}
			if _, active := used[link.ID]; active {
				return fmt.Errorf("%w: node %s changes active fabric link %s in place; introduce a new link ID/interface first", ErrUnsafeRollout, nodeID, link.ID)
			}
		}
	}
	return nil
}

func selectCanary(planID string, forwardIDs []string, percent uint8) ([]string, []string) {
	if percent >= 100 || len(forwardIDs) < 2 {
		return nil, append([]string(nil), forwardIDs...)
	}
	type candidate struct {
		id   string
		hash [32]byte
	}
	candidates := make([]candidate, 0, len(forwardIDs))
	for _, forwardID := range forwardIDs {
		candidates = append(candidates, candidate{id: forwardID, hash: sha256.Sum256([]byte(planID + "\x00" + forwardID))})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].hash == candidates[j].hash {
			return candidates[i].id < candidates[j].id
		}
		return string(candidates[i].hash[:]) < string(candidates[j].hash[:])
	})
	count := (len(candidates)*int(percent) + 99) / 100
	if count <= 0 || count >= len(candidates) {
		return nil, append([]string(nil), forwardIDs...)
	}
	canary := make([]string, 0, count)
	remainder := make([]string, 0, len(candidates)-count)
	for index, value := range candidates {
		if index < count {
			canary = append(canary, value.id)
		} else {
			remainder = append(remainder, value.id)
		}
	}
	sort.Strings(canary)
	sort.Strings(remainder)
	return canary, remainder
}
