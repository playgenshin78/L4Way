package management

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
)

type nodeView struct {
	store.NodeSummary
	Online          bool                      `json:"online"`
	Status          string                    `json:"status"`
	Labels          []string                  `json:"labels"`
	ListenIPs       []string                  `json:"listen_ips"`
	ForwardsCount   uint32                    `json:"forwards_count"`
	ProtocolBlocks  *spec.ProtocolBlockPolicy `json:"protocol_blocks,omitempty"`
	ResourceVersion uint64                    `json:"resource_version"`
}

func (s *Server) handleListNodes(writer http.ResponseWriter, request *http.Request) {
	limit, offset := pagination(request)
	nodes, err := s.repository.ListNodes(request.Context(), 500, 0)
	if err != nil {
		s.internalError(writer, "list nodes", err)
		return
	}
	session := sessionFromContext(request.Context())
	allowed := map[string]bool(nil)
	tenantAllowedListenIPs := map[string]bool(nil)
	if session.Account.Role == iam.RoleTenant {
		policy, err := s.repository.TenantPolicy(request.Context(), session.Account.TenantID)
		if err != nil {
			s.writeRepositoryError(writer, err)
			return
		}
		allowed = make(map[string]bool, len(policy.AllowedIngressNodes)+len(policy.AllowedExitNodes))
		for _, nodeID := range policy.AllowedIngressNodes {
			allowed[nodeID] = true
		}
		for _, nodeID := range policy.AllowedExitNodes {
			allowed[nodeID] = true
		}
		tenantAllowedListenIPs = make(map[string]bool, len(policy.AllowedListenIPs))
		for _, address := range policy.AllowedListenIPs {
			tenantAllowedListenIPs[address] = true
		}
	}
	now := s.config.Now().UTC()
	planRecord, planErr := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID)
	planRevision := uint64(1)
	labels := make(map[string][]string)
	listenIPs := make(map[string]map[string]bool)
	forwardCounts := make(map[string]uint32)
	protocolBlocks := make(map[string]*spec.ProtocolBlockPolicy)
	if planErr == nil {
		planRevision = planRecord.Plan.Revision
		for _, planNode := range planRecord.Plan.Nodes {
			values := make([]string, 0, len(planNode.Labels))
			for key, value := range planNode.Labels {
				values = append(values, key+"="+value)
			}
			sort.Strings(values)
			labels[planNode.ID] = values
			if listenIPs[planNode.ID] == nil {
				listenIPs[planNode.ID] = make(map[string]bool)
			}
			for _, address := range planNode.ListenIPs {
				listenIPs[planNode.ID][address.String()] = true
			}
			if session.Account.Role == iam.RoleOwner && planNode.ProtocolBlocks != nil && planNode.ProtocolBlocks.Any() {
				policy := *planNode.ProtocolBlocks
				protocolBlocks[planNode.ID] = &policy
			}
		}
		for _, forward := range planRecord.Plan.Forwards {
			counted := make(map[string]struct{}, len(forward.Ingress.NodeIDs)+1)
			for _, nodeID := range forward.Ingress.NodeIDs {
				if _, exists := counted[nodeID]; !exists {
					forwardCounts[nodeID]++
					counted[nodeID] = struct{}{}
				}
				if listenIPs[nodeID] == nil {
					listenIPs[nodeID] = make(map[string]bool)
				}
				listenIPs[nodeID][forward.Listen.Address.String()] = true
			}
			if forward.Exit != nil {
				for _, nodeID := range forward.Exit.NodeIDs {
					if _, exists := counted[nodeID]; !exists {
						forwardCounts[nodeID]++
						counted[nodeID] = struct{}{}
					}
				}
			}
		}
	}
	items := make([]nodeView, 0, len(nodes))
	for _, node := range nodes {
		if allowed != nil && (!allowed[node.ID] || node.RevokedAt != nil) {
			continue
		}
		view := nodeView{
			NodeSummary: node, Status: "pending", Labels: labels[node.ID],
			ForwardsCount: forwardCounts[node.ID], ProtocolBlocks: protocolBlocks[node.ID], ResourceVersion: planRevision,
		}
		if view.Labels == nil {
			view.Labels = []string{}
		}
		for address := range listenIPs[node.ID] {
			view.ListenIPs = append(view.ListenIPs, address)
		}
		sort.Strings(view.ListenIPs)
		view.ListenIPs = uniqueStrings(view.ListenIPs)
		if tenantAllowedListenIPs != nil {
			filtered := view.ListenIPs[:0]
			for _, address := range view.ListenIPs {
				if tenantAllowedListenIPs[address] {
					filtered = append(filtered, address)
				}
			}
			view.ListenIPs = filtered
		}
		switch {
		case node.RevokedAt != nil:
			view.Status = "revoked"
		case node.LastSeenAt != nil && now.Sub(node.LastSeenAt.UTC()) <= s.config.NodeOfflineAfter:
			view.Online = true
			view.Status = "online"
		case node.LastSeenAt != nil:
			view.Status = "offline"
		}
		items = append(items, view)
	}
	start := offset
	if start > len(items) {
		start = len(items)
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	writeData(writer, http.StatusOK, map[string]any{"items": items[start:end], "limit": limit, "offset": offset, "total": len(items)})
}

func (s *Server) handleUpdateNodeProtocolBlocks(writer http.ResponseWriter, request *http.Request) {
	s.planMutationMu.RLock()
	defer s.planMutationMu.RUnlock()

	var input struct {
		ResourceVersion uint64                   `json:"resource_version"`
		ProtocolBlocks  spec.ProtocolBlockPolicy `json:"protocol_blocks"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.ResourceVersion == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "resource_version is required")
		return
	}
	nodeID := request.PathValue("nodeID")
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	record, err := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	if input.ResourceVersion != record.Plan.Revision {
		s.writeRepositoryError(writer, iam.ErrConflict)
		return
	}
	plan := record.Plan.Canonical()
	nodeIndex := -1
	for index := range plan.Nodes {
		if plan.Nodes[index].ID == nodeID {
			nodeIndex = index
			break
		}
	}
	if nodeIndex < 0 {
		writeError(writer, http.StatusConflict, "node_not_configured", "节点尚未加入转发配置，连接并完成初始化后才能设置协议拦截")
		return
	}
	current := spec.ProtocolBlockPolicy{}
	if plan.Nodes[nodeIndex].ProtocolBlocks != nil {
		current = *plan.Nodes[nodeIndex].ProtocolBlocks
	}
	if current == input.ProtocolBlocks {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if input.ProtocolBlocks.Any() {
		policy := input.ProtocolBlocks
		plan.Nodes[nodeIndex].ProtocolBlocks = &policy
	} else {
		plan.Nodes[nodeIndex].ProtocolBlocks = nil
	}
	plan.Revision = record.MaximumRevision + 1
	session := sessionFromContext(request.Context())
	result, err := s.applyManagementPlan(request, session, plan)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	s.auditSession(request.Context(), request, session, "node.protocol_blocks.update", "node", nodeID, "success", map[string]any{
		"protocol_blocks": input.ProtocolBlocks, "plan_revision": plan.Revision, "rollout_id": result.RolloutID,
	})
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNodeInstallCommand(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		NodeID     string `json:"node_id"`
		TTLSeconds uint32 `json:"ttl_seconds,omitempty"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := spec.ValidateIdentifier("node_id", input.NodeID); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.TTLSeconds == 0 {
		input.TTLSeconds = 900
	}
	if input.TTLSeconds < 60 || input.TTLSeconds > 86_400 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "ttl_seconds must be between 60 and 86400")
		return
	}
	if !validBootstrapAddress(s.config.PublicEnrollmentAddress) || !validBootstrapAddress(s.config.PublicControlAddress) {
		writeError(writer, http.StatusConflict, "node_install_not_configured", "public enrollment and control addresses must be configured on the Controller")
		return
	}
	controllerPublicKey, err := securechannel.ParsePublicKey(s.config.ControllerPublicKey)
	if err != nil {
		s.internalError(writer, "read Controller bootstrap identity", errors.New("Controller public key is not configured"))
		return
	}
	token, expiresAt, err := s.repository.CreateEnrollmentToken(request.Context(), input.NodeID, time.Duration(input.TTLSeconds)*time.Second)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	bundle := struct {
		Version                  int       `json:"version"`
		NodeID                   string    `json:"node_id"`
		Token                    string    `json:"token"`
		ExpiresAt                time.Time `json:"expires_at"`
		ControllerPublicKey      string    `json:"controller_public_key"`
		ControllerKeyFingerprint string    `json:"controller_key_fingerprint"`
		EnrollmentAddress        string    `json:"enrollment_address"`
		ControlAddress           string    `json:"control_address"`
	}{
		Version: 1, NodeID: input.NodeID, Token: token, ExpiresAt: expiresAt,
		ControllerPublicKey: s.config.ControllerPublicKey, ControllerKeyFingerprint: securechannel.Fingerprint(controllerPublicKey),
		EnrollmentAddress: s.config.PublicEnrollmentAddress, ControlAddress: s.config.PublicControlAddress,
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		s.internalError(writer, "encode node installation bundle", err)
		return
	}
	bundleBase64 := base64.RawURLEncoding.EncodeToString(encoded)
	command := "sudo ./flux-agent install --bundle-base64 '" + bundleBase64 + "' --enable-fabric"
	prerequisite := "先把与节点架构匹配的 flux-agent 程序复制到 Linux 主机，再执行命令"
	if validHTTPSDownloadURL(s.config.NodeInstallerURL) && validHTTPSDownloadURL(s.config.NodeReleaseURL) {
		command = "set -o pipefail; curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 '" +
			s.config.NodeInstallerURL + "' | sudo bash -s -- agent --release-url '" +
			s.config.NodeReleaseURL + "' --bundle-base64 '" + bundleBase64 + "' --enable-fabric"
		prerequisite = "在 Linux 节点终端执行；命令会下载并校验发行包，然后完成接入"
	}
	session := sessionFromContext(request.Context())
	s.auditSession(request.Context(), request, session, "node.install_command.create", "node", input.NodeID, "success", map[string]any{"expires_at": expiresAt})
	writeData(writer, http.StatusCreated, map[string]any{
		"node_id": input.NodeID, "expires_at": expiresAt, "install_command": command, "bundle_base64": bundleBase64,
		"prerequisite": prerequisite,
	})
}

func (s *Server) handleRevokeNode(writer http.ResponseWriter, request *http.Request) {
	nodeID := request.PathValue("nodeID")
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.repository.RevokeNode(request.Context(), nodeID, s.config.Now().UTC()); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	session := sessionFromContext(request.Context())
	s.auditSession(request.Context(), request, session, "node.revoke", "node", nodeID, "success", nil)
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteNode(writer http.ResponseWriter, request *http.Request) {
	nodeID := request.PathValue("nodeID")
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.repository.DeletePendingNode(request.Context(), nodeID); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	session := sessionFromContext(request.Context())
	s.auditSession(request.Context(), request, session, "node.delete", "node", nodeID, "success", map[string]any{"state": "pending"})
	writer.WriteHeader(http.StatusNoContent)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func validBootstrapAddress(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "\r\n\t \x00") {
		return false
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsed != 0
}

func validHTTPSDownloadURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "'\"#\\\r\n\t \x00") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	return true
}
