package management

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"flux.local/flux/internal/cluster"
	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/spec"
)

type forwardEndpointPayload struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type forwardInput struct {
	TenantID        string                 `json:"tenant_id,omitempty"`
	Protocols       []spec.Protocol        `json:"protocols"`
	Listen          spec.Endpoint          `json:"listen"`
	Target          forwardEndpointPayload `json:"target"`
	PathMode        spec.PathMode          `json:"path_mode"`
	IngressNodeID   string                 `json:"ingress_node_id"`
	ExitNodeID      string                 `json:"exit_node_id,omitempty"`
	RateLimit       *spec.RateLimitSpec    `json:"rate_limit,omitempty"`
	TrafficQuota    *spec.TrafficQuotaSpec `json:"traffic_quota,omitempty"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	Enabled         *bool                  `json:"enabled,omitempty"`
	ResourceVersion uint64                 `json:"resource_version,omitempty"`
}

type forwardView struct {
	ID              string                 `json:"id"`
	TenantID        string                 `json:"tenant_id"`
	TenantName      string                 `json:"tenant_name"`
	Protocols       []spec.Protocol        `json:"protocols"`
	Listen          spec.Endpoint          `json:"listen"`
	Target          forwardEndpointPayload `json:"target"`
	PathMode        spec.PathMode          `json:"path_mode"`
	IngressNodeID   string                 `json:"ingress_node_id"`
	IngressNodeName string                 `json:"ingress_node_name"`
	ExitNodeID      string                 `json:"exit_node_id,omitempty"`
	ExitNodeName    string                 `json:"exit_node_name,omitempty"`
	RateLimit       *spec.RateLimitSpec    `json:"rate_limit,omitempty"`
	TrafficQuota    *spec.TrafficQuotaSpec `json:"traffic_quota,omitempty"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	Lifecycle       spec.Lifecycle         `json:"lifecycle"`
	ResourceVersion uint64                 `json:"resource_version"`
	Editable        bool                   `json:"editable"`
	PlanRevision    uint64                 `json:"plan_revision"`
}

func (s *Server) handleListForwards(writer http.ResponseWriter, request *http.Request) {
	session := sessionFromContext(request.Context())
	record, err := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	items := make([]forwardView, 0, len(record.Plan.Forwards))
	for index := range record.Plan.Forwards {
		forward := record.Plan.Forwards[index]
		if session.Account.Role == iam.RoleTenant && forward.UserID != session.Account.TenantID {
			continue
		}
		view, err := viewForForward(record.Plan, index)
		if err != nil {
			s.internalError(writer, "render forward", err)
			return
		}
		view = s.decorateForwardView(request, view)
		items = append(items, view)
	}
	writeData(writer, http.StatusOK, map[string]any{"items": items, "plan_id": record.Plan.ID, "plan_revision": record.Plan.Revision})
}

func (s *Server) handleGetForward(writer http.ResponseWriter, request *http.Request) {
	session := sessionFromContext(request.Context())
	record, index, err := s.managementForward(request, session)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	view, err := viewForForward(record.Plan, index)
	if err != nil {
		s.internalError(writer, "render forward", err)
		return
	}
	view = s.decorateForwardView(request, view)
	writeData(writer, http.StatusOK, view)
}

func (s *Server) handleCreateForward(writer http.ResponseWriter, request *http.Request) {
	s.planMutationMu.RLock()
	defer s.planMutationMu.RUnlock()

	var input forwardInput
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.ResourceVersion != 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "resource_version must be omitted when creating a forward")
		return
	}
	session := sessionFromContext(request.Context())
	tenantID, err := s.forwardTenantID(request, session, input.TenantID, true)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	record, err := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	target, err := s.resolveForwardTarget(request.Context(), input.Target)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	forwardID, err := iam.NewID("fwd")
	if err != nil {
		s.internalError(writer, "generate forward identity", err)
		return
	}
	forward, pool, err := buildManagementForward(forwardID, tenantID, input, target, 1)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateManagementListenIP(record.Plan, forward); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.authorizeForward(request, session, forward, pool.Backends[0].Target, tenantForwardCount(record.Plan, tenantID)); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	plan := record.Plan.Canonical()
	if err := s.syncManagedUserPolicy(request, &plan, tenantID); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	plan.Forwards = append(plan.Forwards, forward)
	plan.BackendPools = append(plan.BackendPools, pool)
	plan.Revision = record.MaximumRevision + 1
	result, err := s.applyManagementPlan(request, session, plan)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	index := forwardIndex(plan, forwardID)
	view, err := viewForForward(plan, index)
	if err != nil {
		s.internalError(writer, "render created forward", err)
		return
	}
	view = s.decorateForwardView(request, view)
	s.auditSession(request.Context(), request, session, "forward.create", "forward", forwardID, "success", map[string]any{"plan_revision": plan.Revision, "rollout_id": result.RolloutID})
	writeData(writer, http.StatusCreated, map[string]any{"forward": view, "rollout": result})
}

func (s *Server) handleUpdateForward(writer http.ResponseWriter, request *http.Request) {
	s.planMutationMu.RLock()
	defer s.planMutationMu.RUnlock()

	var input forwardInput
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.ResourceVersion == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "resource_version is required")
		return
	}
	session := sessionFromContext(request.Context())
	record, index, err := s.managementForward(request, session)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	existing := record.Plan.Forwards[index]
	if input.ResourceVersion != existing.ResourceVersion {
		s.writeRepositoryError(writer, iam.ErrConflict)
		return
	}
	if input.TenantID != "" && input.TenantID != existing.UserID {
		s.writeRepositoryError(writer, iam.ErrForbidden)
		return
	}
	if existing.Lifecycle == spec.LifecycleDraining || existing.Lifecycle == spec.LifecycleForceDeleting {
		s.writeRepositoryError(writer, fmt.Errorf("%w: deleting forwards cannot be edited", iam.ErrConflict))
		return
	}
	poolIndex, editable := editablePool(record.Plan, existing.BackendPoolID)
	if !editable {
		s.writeRepositoryError(writer, fmt.Errorf("%w: this forward uses a shared or multi-target backend pool", iam.ErrConflict))
		return
	}
	target, err := s.resolveForwardTarget(request.Context(), input.Target)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	updated, _, err := buildManagementForward(existing.ID, existing.UserID, input, target, existing.ResourceVersion+1)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	updated.BackendPoolID = existing.BackendPoolID
	if input.Enabled == nil {
		updated.Lifecycle = existing.Lifecycle
	}
	if updated.Listen != existing.Listen {
		if err := validateManagementListenIP(record.Plan, updated); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	count := tenantForwardCount(record.Plan, existing.UserID)
	if count != 0 {
		count--
	}
	if err := s.authorizeForward(request, session, updated, target, count); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	plan := record.Plan.Canonical()
	if err := s.syncManagedUserPolicy(request, &plan, existing.UserID); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	plan.Forwards[index] = updated
	pool := plan.BackendPools[poolIndex]
	pool.ResourceVersion++
	pool.Backends[0].Target = target
	pool.Backends[0].ResourceVersion++
	plan.BackendPools[poolIndex] = pool
	plan.Revision = record.MaximumRevision + 1
	result, err := s.applyManagementPlan(request, session, plan)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	view, err := viewForForward(plan, index)
	if err != nil {
		s.internalError(writer, "render updated forward", err)
		return
	}
	view = s.decorateForwardView(request, view)
	s.auditSession(request.Context(), request, session, "forward.update", "forward", existing.ID, "success", map[string]any{"plan_revision": plan.Revision, "rollout_id": result.RolloutID})
	writeData(writer, http.StatusOK, map[string]any{"forward": view, "rollout": result})
}

func (s *Server) handleDeleteForward(writer http.ResponseWriter, request *http.Request) {
	s.planMutationMu.RLock()
	defer s.planMutationMu.RUnlock()

	session := sessionFromContext(request.Context())
	record, index, err := s.managementForward(request, session)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	expected, err := strconv.ParseUint(request.URL.Query().Get("resource_version"), 10, 64)
	if err != nil || expected == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "resource_version query parameter is required")
		return
	}
	forward := record.Plan.Forwards[index]
	if expected != forward.ResourceVersion {
		s.writeRepositoryError(writer, iam.ErrConflict)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("mode")))
	if mode == "" {
		mode = "drain"
	}
	now := s.config.Now().UTC()
	switch mode {
	case "force":
		forward.Lifecycle = spec.LifecycleForceDeleting
		forward.DrainDeadline = nil
	case "drain":
		drainSeconds := uint64(300)
		if raw := strings.TrimSpace(request.URL.Query().Get("drain_seconds")); raw != "" {
			drainSeconds, err = strconv.ParseUint(raw, 10, 32)
			if err != nil || drainSeconds < 30 || drainSeconds > 86_400 {
				writeError(writer, http.StatusBadRequest, "invalid_request", "drain_seconds must be between 30 and 86400")
				return
			}
		}
		deadline := now.Add(time.Duration(drainSeconds) * time.Second)
		forward.Lifecycle = spec.LifecycleDraining
		forward.DrainDeadline = &deadline
	default:
		writeError(writer, http.StatusBadRequest, "invalid_request", "delete mode must be drain or force")
		return
	}
	forward.ResourceVersion++
	plan := record.Plan.Canonical()
	plan.Forwards[index] = forward
	plan.Revision = record.MaximumRevision + 1
	result, err := s.applyManagementPlan(request, session, plan)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	view, err := viewForForward(plan, index)
	if err != nil {
		s.internalError(writer, "render deleting forward", err)
		return
	}
	view = s.decorateForwardView(request, view)
	s.auditSession(request.Context(), request, session, "forward.delete."+mode, "forward", forward.ID, "success", map[string]any{"plan_revision": plan.Revision, "rollout_id": result.RolloutID})
	writeData(writer, http.StatusAccepted, map[string]any{"forward": view, "rollout": result})
}

func (s *Server) managementForward(request *http.Request, session iam.Session) (store.ActiveClusterPlan, int, error) {
	record, err := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID)
	if err != nil {
		return store.ActiveClusterPlan{}, -1, err
	}
	index := forwardIndex(record.Plan, request.PathValue("forwardID"))
	if index < 0 {
		return store.ActiveClusterPlan{}, -1, iam.ErrNotFound
	}
	if session.Account.Role == iam.RoleTenant && record.Plan.Forwards[index].UserID != session.Account.TenantID {
		return store.ActiveClusterPlan{}, -1, iam.ErrForbidden
	}
	return record, index, nil
}

func (s *Server) forwardTenantID(request *http.Request, session iam.Session, requested string, requireActive bool) (string, error) {
	requested = strings.TrimSpace(requested)
	if session.Account.Role == iam.RoleTenant {
		if requested != "" && requested != session.Account.TenantID {
			return "", iam.ErrForbidden
		}
		return session.Account.TenantID, nil
	}
	if requested == "" {
		return "owner", nil
	}
	if err := iam.ValidateInternalID("tenant_id", requested); err != nil {
		return "", err
	}
	if requested == "owner" {
		return requested, nil
	}
	tenant, err := s.repository.TenantByID(request.Context(), requested)
	if err != nil {
		return "", err
	}
	if requireActive && (tenant.Status != iam.StatusActive || tenant.ExpiresAt != nil && !s.config.Now().UTC().Before(*tenant.ExpiresAt)) {
		return "", fmt.Errorf("%w: tenant is disabled or expired", iam.ErrForbidden)
	}
	return requested, nil
}

func (s *Server) authorizeForward(request *http.Request, session iam.Session, forward cluster.Forward, target spec.Endpoint, currentCount uint32) error {
	if session.Account.Role == iam.RoleOwner && forward.UserID == "owner" {
		return nil
	}
	if session.Account.Role == iam.RoleTenant && forward.UserID != session.Account.TenantID {
		return iam.ErrForbidden
	}
	tenant, err := s.repository.TenantByID(request.Context(), forward.UserID)
	if err != nil {
		return err
	}
	policy, err := s.repository.TenantPolicy(request.Context(), forward.UserID)
	if err != nil {
		return err
	}
	resolved := spec.ForwardSpec{
		ID: forward.ID, UserID: forward.UserID, Protocols: forward.Protocols, Listen: forward.Listen, Target: target,
		PathMode: forward.PathMode, SNAT: forward.SNAT, RateLimit: forward.RateLimit, TrafficQuota: forward.TrafficQuota,
		ExpiresAt: forward.ExpiresAt, Lifecycle: forward.Lifecycle, ResourceVersion: forward.ResourceVersion,
	}
	if len(forward.Ingress.NodeIDs) == 1 {
		resolved.IngressNodeID = forward.Ingress.NodeIDs[0]
	}
	if forward.Exit != nil && len(forward.Exit.NodeIDs) == 1 {
		resolved.ExitNodeID = forward.Exit.NodeIDs[0]
	}
	return policy.AuthorizeForward(resolved, currentCount, tenant.ExpiresAt, s.config.Now().UTC())
}

func (s *Server) applyManagementPlan(request *http.Request, session iam.Session, plan cluster.Plan) (store.ClusterApplyResult, error) {
	actor := string(session.Account.Role) + ":" + session.Account.Username
	return s.repository.ApplyClusterPlan(request.Context(), plan, actor)
}

func buildManagementForward(id, tenantID string, input forwardInput, target spec.Endpoint, resourceVersion uint64) (cluster.Forward, cluster.BackendPool, error) {
	if err := iam.ValidateInternalID("forward_id", id); err != nil {
		return cluster.Forward{}, cluster.BackendPool{}, err
	}
	if err := iam.ValidateInternalID("tenant_id", tenantID); err != nil {
		return cluster.Forward{}, cluster.BackendPool{}, err
	}
	if len(input.Protocols) == 0 {
		return cluster.Forward{}, cluster.BackendPool{}, errors.New("protocols must not be empty")
	}
	if err := iam.ValidateInternalID("ingress_node_id", input.IngressNodeID); err != nil {
		return cluster.Forward{}, cluster.BackendPool{}, err
	}
	forward := cluster.Forward{
		ID: id, UserID: tenantID, Protocols: append([]spec.Protocol(nil), input.Protocols...), Listen: input.Listen,
		PathMode: input.PathMode, Ingress: cluster.NodeSelector{NodeIDs: []string{input.IngressNodeID}},
		BackendPoolID: "pool_" + id, SNAT: spec.SNATSpec{Mode: spec.SNATMasquerade}, RateLimit: input.RateLimit,
		TrafficQuota: input.TrafficQuota, ExpiresAt: input.ExpiresAt, Lifecycle: spec.LifecycleActive, ResourceVersion: resourceVersion,
	}
	if input.Enabled != nil && !*input.Enabled {
		forward.Lifecycle = spec.LifecyclePaused
	}
	switch input.PathMode {
	case spec.PathDirect:
		if strings.TrimSpace(input.ExitNodeID) != "" {
			return cluster.Forward{}, cluster.BackendPool{}, errors.New("exit_node_id must be empty for direct forwarding")
		}
	case spec.PathViaExit:
		if err := iam.ValidateInternalID("exit_node_id", input.ExitNodeID); err != nil {
			return cluster.Forward{}, cluster.BackendPool{}, err
		}
		forward.Exit = &cluster.NodeSelector{NodeIDs: []string{input.ExitNodeID}}
		forward.FailureDomainPolicy = cluster.FailureDomainAny
	default:
		return cluster.Forward{}, cluster.BackendPool{}, errors.New("path_mode must be direct or via_exit")
	}
	pool := cluster.BackendPool{
		ID: forward.BackendPoolID, ResourceVersion: resourceVersion,
		Backends: []cluster.Backend{{ID: "primary", Target: target, Priority: 1, ResourceVersion: resourceVersion}},
	}
	return forward, pool, nil
}

func viewForForward(plan cluster.Plan, forwardIndex int) (forwardView, error) {
	if forwardIndex < 0 || forwardIndex >= len(plan.Forwards) {
		return forwardView{}, iam.ErrNotFound
	}
	forward := plan.Forwards[forwardIndex]
	poolIndex, editable := editablePool(plan, forward.BackendPoolID)
	if poolIndex < 0 || len(plan.BackendPools[poolIndex].Backends) == 0 {
		return forwardView{}, fmt.Errorf("forward %s references an empty or missing backend pool", forward.ID)
	}
	view := forwardView{
		ID: forward.ID, TenantID: forward.UserID, Protocols: append([]spec.Protocol(nil), forward.Protocols...),
		Listen: forward.Listen, Target: forwardTargetPayload(plan.BackendPools[poolIndex].Backends[0].Target), PathMode: forward.PathMode,
		RateLimit: forward.RateLimit, TrafficQuota: forward.TrafficQuota, ExpiresAt: forward.ExpiresAt,
		Lifecycle: forward.Lifecycle, ResourceVersion: forward.ResourceVersion, Editable: editable, PlanRevision: plan.Revision,
	}
	if len(forward.Ingress.NodeIDs) == 1 {
		view.IngressNodeID = forward.Ingress.NodeIDs[0]
		view.IngressNodeName = view.IngressNodeID
	}
	if forward.Exit != nil && len(forward.Exit.NodeIDs) == 1 {
		view.ExitNodeID = forward.Exit.NodeIDs[0]
		view.ExitNodeName = view.ExitNodeID
	}
	return view, nil
}

func (s *Server) resolveForwardTarget(ctx context.Context, input forwardEndpointPayload) (spec.Endpoint, error) {
	value := strings.TrimSpace(input.Address)
	if value == "" {
		return spec.Endpoint{}, errors.New("请输入目标 IPv4 地址或域名")
	}
	if input.Port == 0 {
		return spec.Endpoint{}, errors.New("目标端口必须在 1 到 65535 之间")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return spec.Endpoint{}, errors.New("当前仅支持具体的 IPv4 目标地址")
		}
		return spec.Endpoint{Address: address, Port: input.Port}, nil
	}
	hostname, err := spec.NormalizeHostname(value)
	if err != nil {
		return spec.Endpoint{}, errors.New("目标地址必须是有效的 IPv4 地址或域名")
	}
	resolveContext, cancel := context.WithTimeout(ctx, s.config.TargetResolveTimeout)
	defer cancel()
	address, err := s.config.ResolveTargetIPv4(resolveContext, hostname)
	if err != nil {
		return spec.Endpoint{}, fmt.Errorf("域名 %s 当前无法解析到 IPv4 地址", hostname)
	}
	address = address.Unmap()
	if !address.IsValid() || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return spec.Endpoint{}, fmt.Errorf("域名 %s 没有可用的 IPv4 地址", hostname)
	}
	return spec.Endpoint{Address: address, Hostname: hostname, Port: input.Port}, nil
}

func forwardTargetPayload(endpoint spec.Endpoint) forwardEndpointPayload {
	address := endpoint.Address.String()
	if endpoint.Hostname != "" {
		address = endpoint.Hostname
	}
	return forwardEndpointPayload{Address: address, Port: endpoint.Port}
}

func (s *Server) decorateForwardView(request *http.Request, view forwardView) forwardView {
	if view.TenantID == "owner" {
		view.TenantName = "Owner"
		return view
	}
	view.TenantName = view.TenantID
	if tenant, err := s.repository.TenantByID(request.Context(), view.TenantID); err == nil {
		view.TenantName = tenant.Name
	}
	return view
}

func editablePool(plan cluster.Plan, poolID string) (int, bool) {
	managedName := strings.HasPrefix(poolID, "pool_fwd_")
	poolIndex := -1
	for index := range plan.BackendPools {
		if plan.BackendPools[index].ID == poolID {
			poolIndex = index
			break
		}
	}
	if poolIndex < 0 || !managedName || len(plan.BackendPools[poolIndex].Backends) != 1 || plan.BackendPools[poolIndex].Backends[0].ID != "primary" {
		return poolIndex, false
	}
	references := 0
	for _, forward := range plan.Forwards {
		if forward.BackendPoolID == poolID {
			references++
		}
	}
	return poolIndex, references == 1
}

func forwardIndex(plan cluster.Plan, forwardID string) int {
	for index := range plan.Forwards {
		if plan.Forwards[index].ID == forwardID {
			return index
		}
	}
	return -1
}

func tenantForwardCount(plan cluster.Plan, tenantID string) uint32 {
	var count uint32
	for _, forward := range plan.Forwards {
		if forward.UserID == tenantID && forward.Lifecycle != spec.LifecycleForceDeleting {
			count++
		}
	}
	return count
}

func validateManagementListenIP(plan cluster.Plan, forward cluster.Forward) error {
	if len(forward.Ingress.NodeIDs) != 1 {
		return errors.New("management forward ingress node is invalid")
	}
	nodeID := forward.Ingress.NodeIDs[0]
	for _, node := range plan.Nodes {
		if node.ID != nodeID {
			continue
		}
		for _, address := range node.ListenIPs {
			if address.Unmap() == forward.Listen.Address.Unmap() {
				return nil
			}
		}
		return fmt.Errorf("listen address %s is not configured in ingress node %s listen_ips", forward.Listen.Address, nodeID)
	}
	return fmt.Errorf("ingress node %s is invalid", nodeID)
}

func (s *Server) syncManagedUserPolicy(request *http.Request, plan *cluster.Plan, tenantID string) error {
	if tenantID == "owner" {
		return nil
	}
	policy, err := s.repository.TenantPolicy(request.Context(), tenantID)
	if err != nil {
		return err
	}
	expected, err := policy.DataPlanePolicy()
	if err != nil {
		return err
	}
	plan.UserPolicies = replaceUserPolicy(plan.UserPolicies, tenantID, expected)
	return nil
}

func replaceUserPolicy(policies []spec.UserPolicySpec, userID string, expected *spec.UserPolicySpec) []spec.UserPolicySpec {
	result := make([]spec.UserPolicySpec, 0, len(policies)+1)
	for _, policy := range policies {
		if policy.UserID != userID {
			result = append(result, policy)
		}
	}
	if expected != nil {
		result = append(result, *expected)
	}
	return result
}
