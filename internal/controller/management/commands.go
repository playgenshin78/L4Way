package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/cluster"
	controllercontrol "flux.local/flux/internal/controller/control"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/spec"
)

func (s *Server) handleForwardTCPCheck(writer http.ResponseWriter, request *http.Request) {
	if s.config.NodeCommands == nil {
		writeError(writer, http.StatusServiceUnavailable, "node_commands_unavailable", "节点控制通道尚未启用")
		return
	}
	session := sessionFromContext(request.Context())
	record, index, err := s.managementForward(request, session)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	forward := record.Plan.Forwards[index]
	if !containsProtocol(forward.Protocols, spec.ProtocolTCP) {
		writeError(writer, http.StatusConflict, "tcp_not_enabled", "这条转发没有启用 TCP，无法执行 TCP 检查")
		return
	}
	poolIndex, _ := editablePool(record.Plan, forward.BackendPoolID)
	if poolIndex < 0 || len(record.Plan.BackendPools[poolIndex].Backends) == 0 {
		s.internalError(writer, "read TCP check target", errors.New("forward target pool is missing"))
		return
	}
	executionNode := ""
	if forward.PathMode == spec.PathDirect && len(forward.Ingress.NodeIDs) == 1 {
		executionNode = forward.Ingress.NodeIDs[0]
	} else if forward.PathMode == spec.PathViaExit && forward.Exit != nil && len(forward.Exit.NodeIDs) == 1 {
		// A tunnel forward reaches the target from its exit node. The one-shot
		// tcping measures connect latency only; it never sends a speed-test payload.
		executionNode = forward.Exit.NodeIDs[0]
	}
	if executionNode == "" {
		writeError(writer, http.StatusConflict, "forward_not_ready", "转发节点尚未确定，暂时无法检查")
		return
	}
	node, err := s.nodeSummary(request.Context(), executionNode)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	if !nodeHasCapability(node, "diagnostics.tcp-connect", 1) {
		writeError(writer, http.StatusConflict, "agent_upgrade_required", "节点程序版本过旧，请先升级 Agent")
		return
	}
	target := record.Plan.BackendPools[poolIndex].Backends[0].Target
	commandContext, cancel := context.WithTimeout(request.Context(), 8*time.Second)
	defer cancel()
	result, err := s.config.NodeCommands.Dispatch(commandContext, executionNode, controllercontrol.CommandRequest{
		Kind: controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK, Deadline: s.config.Now().UTC().Add(5 * time.Second),
		Address: target.Address.String(), Port: uint32(target.Port),
	})
	if err != nil {
		s.writeNodeCommandError(writer, err)
		return
	}
	checkedAt := s.config.Now().UTC()
	s.auditSession(request.Context(), request, session, "forward.tcp_check", "forward", forward.ID, "success", map[string]any{
		"reachable": result.Success, "latency_ms": float64(result.LatencyMicros) / 1000,
		"execution_node_id": executionNode, "error_code": result.ErrorCode,
	})
	writeData(writer, http.StatusOK, map[string]any{
		"forward_id": forward.ID, "reachable": result.Success, "checked_at": checkedAt,
		"latency_ms": float64(result.LatencyMicros) / 1000, "execution_node_id": executionNode, "message": result.ErrorMessage,
	})
}

func (s *Server) handleUpgradeNode(writer http.ResponseWriter, request *http.Request) {
	if s.config.NodeCommands == nil {
		writeError(writer, http.StatusServiceUnavailable, "node_commands_unavailable", "节点控制通道尚未启用")
		return
	}
	nodeID := request.PathValue("nodeID")
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !validHTTPSDownloadURL(s.config.NodeReleaseURL) {
		writeError(writer, http.StatusConflict, "agent_upgrade_not_configured", "Controller 尚未配置 Agent 发行包地址")
		return
	}
	node, err := s.nodeSummary(request.Context(), nodeID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	if node.RevokedAt != nil || node.AgentVersion == "" {
		writeError(writer, http.StatusConflict, "node_not_active", "节点尚未接入或已经吊销")
		return
	}
	if !nodeHasCapability(node, "agent.maintenance", 1) {
		writeError(writer, http.StatusConflict, "manual_upgrade_required", "当前 Agent 版本不支持网页升级，请先手动升级一次")
		return
	}
	// Once a maintenance command is queued, a browser disconnect must not
	// abandon its result. In particular, uninstall must still revoke the node
	// identity after the Agent confirms local cleanup.
	commandContext, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 130*time.Second)
	defer cancel()
	result, err := s.config.NodeCommands.Dispatch(commandContext, nodeID, controllercontrol.CommandRequest{
		Kind: controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UPGRADE, Deadline: s.config.Now().UTC().Add(2 * time.Minute),
		ReleaseURL: s.config.NodeReleaseURL, ChecksumURL: checksumURLForRelease(s.config.NodeReleaseURL),
	})
	if err != nil {
		s.writeNodeCommandError(writer, err)
		return
	}
	if !result.Success {
		writeError(writer, commandFailureStatus(result.ErrorCode), result.ErrorCode, result.ErrorMessage)
		return
	}
	session := sessionFromContext(request.Context())
	s.auditSession(commandContext, request, session, "node.upgrade", "node", nodeID, "success", map[string]any{"previous_version": node.AgentVersion})
	writeData(writer, http.StatusAccepted, map[string]any{
		"node_id": nodeID, "status": "restarting", "message": "新版 Agent 已校验并安装，节点正在重启",
	})
}

func checksumURLForRelease(releaseURL string) string {
	parsed, err := url.Parse(releaseURL)
	if err != nil {
		return ""
	}
	parsed.Path += ".sha256"
	return parsed.String()
}

func (s *Server) handleUninstallNode(writer http.ResponseWriter, request *http.Request) {
	s.planMutationMu.Lock()
	defer s.planMutationMu.Unlock()

	if s.config.NodeCommands == nil {
		writeError(writer, http.StatusServiceUnavailable, "node_commands_unavailable", "节点控制通道尚未启用")
		return
	}
	nodeID := request.PathValue("nodeID")
	if err := spec.ValidateIdentifier("node_id", nodeID); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	node, err := s.nodeSummary(request.Context(), nodeID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	if node.RevokedAt != nil || node.AgentVersion == "" {
		writeError(writer, http.StatusConflict, "node_not_active", "节点尚未接入或已经吊销")
		return
	}
	if node.DesiredGeneration != node.AppliedGeneration {
		writeError(writer, http.StatusConflict, "node_not_synced", "节点配置尚未同步完成，暂时不能卸载")
		return
	}
	if !nodeHasCapability(node, "agent.maintenance", 1) {
		writeError(writer, http.StatusConflict, "manual_uninstall_required", "当前 Agent 版本不支持网页卸载")
		return
	}
	planRecord, err := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	if nodeUsedByForward(planRecord.Plan, nodeID) {
		writeError(writer, http.StatusConflict, "node_in_use", "请先迁移或删除这个节点承载的全部转发")
		return
	}
	commandContext, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 100*time.Second)
	defer cancel()
	session := sessionFromContext(request.Context())
	planRevision := planRecord.Plan.Revision
	if detached, removed := planWithoutNode(planRecord.Plan, nodeID); removed {
		detached.Revision = planRecord.MaximumRevision + 1
		actor := string(session.Account.Role) + ":" + session.Account.Username
		if _, err := s.repository.ApplyClusterPlan(commandContext, detached, actor); err != nil {
			s.writeRepositoryError(writer, err)
			return
		}
		planRevision = detached.Revision
	}
	cleanupContext, cleanupCancel := context.WithTimeout(commandContext, 45*time.Second)
	err = s.waitForRetiredNode(cleanupContext, nodeID)
	cleanupCancel()
	if err != nil {
		s.writeNodeCommandError(writer, err)
		return
	}
	result, err := s.config.NodeCommands.Dispatch(commandContext, nodeID, controllercontrol.CommandRequest{
		Kind: controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UNINSTALL, Deadline: s.config.Now().UTC().Add(45 * time.Second),
	})
	if err != nil {
		if errors.Is(err, controllercontrol.ErrCommandConnectionLost) {
			// The Agent may have completed local removal just before the stream
			// broke. The node is already detached and empty, so revoking its
			// identity is the safe deterministic outcome of the Owner's request.
			revokeContext, revokeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			revokeErr := s.repository.RevokeNode(revokeContext, nodeID, s.config.Now().UTC())
			revokeCancel()
			if revokeErr != nil {
				s.writeRepositoryError(writer, revokeErr)
				return
			}
			s.auditSession(context.Background(), request, session, "node.uninstall", "node", nodeID, "success", map[string]any{
				"identity_revoked": true, "local_cleanup_confirmed": false, "plan_revision": planRevision,
			})
			writeData(writer, http.StatusAccepted, map[string]any{
				"node_id": nodeID, "status": "identity_revoked",
				"message": "节点连接在卸载时中断，身份已安全吊销；请在节点上运行卸载脚本确认本地文件已清理",
			})
			return
		}
		s.writeNodeCommandError(writer, err)
		return
	}
	if !result.Success {
		writeError(writer, commandFailureStatus(result.ErrorCode), result.ErrorCode, result.ErrorMessage)
		return
	}
	if err := s.repository.RevokeNode(commandContext, nodeID, s.config.Now().UTC()); err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	s.auditSession(commandContext, request, session, "node.uninstall", "node", nodeID, "success", map[string]any{
		"identity_revoked": true, "plan_revision": planRevision,
	})
	writeData(writer, http.StatusAccepted, map[string]any{
		"node_id": nodeID, "status": "uninstalled", "message": "Agent 已卸载，节点身份已吊销",
	})
}

func (s *Server) waitForRetiredNode(ctx context.Context, nodeID string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		node, err := s.nodeSummary(ctx, nodeID)
		if err != nil {
			return err
		}
		snapshot, exists, err := s.repository.LatestSnapshot(ctx, nodeID)
		if err != nil {
			return err
		}
		if !exists && node.DesiredGeneration == 0 && node.AppliedGeneration == 0 {
			return nil
		}
		if exists && snapshot.Generation == node.DesiredGeneration && node.AppliedGeneration == snapshot.Generation {
			desired, err := spec.DecodeDesiredJSON(snapshot.DesiredStateJSON)
			if err != nil {
				return fmt.Errorf("decode retired node state: %w", err)
			}
			if retiredDesiredState(desired, nodeID) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for node cleanup ACK: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func retiredDesiredState(desired spec.DesiredState, nodeID string) bool {
	return desired.NodeID == nodeID && len(desired.Forwards) == 0 && len(desired.FabricLinks) == 0 &&
		len(desired.HealthChecks) == 0 && len(desired.UserPolicies) == 0 && len(desired.ServiceCIDRs) == 0 &&
		(desired.ProtocolBlocks == nil || !desired.ProtocolBlocks.Any())
}

func planWithoutNode(plan cluster.Plan, nodeID string) (cluster.Plan, bool) {
	result := plan.Canonical()
	nodes := make([]cluster.Node, 0, len(result.Nodes))
	removed := false
	for _, node := range result.Nodes {
		if node.ID == nodeID {
			removed = true
			continue
		}
		links := node.FabricLinks[:0]
		for _, link := range node.FabricLinks {
			if link.PeerNodeID != nodeID {
				links = append(links, link)
			}
		}
		node.FabricLinks = links
		nodes = append(nodes, node)
	}
	result.Nodes = nodes
	return result, removed
}

func (s *Server) nodeSummary(ctx context.Context, nodeID string) (store.NodeSummary, error) {
	nodes, err := s.repository.ListNodes(ctx, 500, 0)
	if err != nil {
		return store.NodeSummary{}, err
	}
	for _, node := range nodes {
		if node.ID == nodeID {
			return node, nil
		}
	}
	return store.NodeSummary{}, store.ErrNodeNotFound
}

func nodeHasCapability(node store.NodeSummary, name string, minimum uint32) bool {
	var capabilities []*controlv1.Capability
	if err := json.Unmarshal(node.Capabilities, &capabilities); err != nil {
		return false
	}
	for _, capability := range capabilities {
		if capability != nil && capability.Name == name && capability.Version >= minimum {
			return true
		}
	}
	return false
}

func nodeUsedByForward(plan cluster.Plan, nodeID string) bool {
	for _, forward := range plan.Forwards {
		for _, candidate := range forward.Ingress.NodeIDs {
			if candidate == nodeID {
				return true
			}
		}
		if forward.Exit != nil {
			for _, candidate := range forward.Exit.NodeIDs {
				if candidate == nodeID {
					return true
				}
			}
		}
	}
	return false
}

func containsProtocol(protocols []spec.Protocol, wanted spec.Protocol) bool {
	for _, protocol := range protocols {
		if protocol == wanted {
			return true
		}
	}
	return false
}

func (s *Server) writeNodeCommandError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controllercontrol.ErrNodeOffline), errors.Is(err, controllercontrol.ErrCommandConnectionLost):
		writeError(writer, http.StatusConflict, "node_offline", "节点当前离线，无法执行操作")
	case errors.Is(err, controllercontrol.ErrCommandQueueFull):
		writeError(writer, http.StatusConflict, "node_busy", "节点操作队列已满，请稍后重试")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeError(writer, http.StatusGatewayTimeout, "node_command_timeout", "等待节点响应超时")
	default:
		s.logger.Error("dispatch node command", "error", err)
		writeError(writer, http.StatusServiceUnavailable, "node_command_failed", "暂时无法向节点发送操作")
	}
}

func commandFailureStatus(code string) int {
	switch strings.TrimSpace(code) {
	case "agent_busy", "configuration_busy", "node_in_use", "nonstandard_installation":
		return http.StatusConflict
	default:
		return http.StatusBadGateway
	}
}

var _ NodeCommander = (*controllercontrol.CommandBroker)(nil)
