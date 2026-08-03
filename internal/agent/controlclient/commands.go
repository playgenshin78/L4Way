package controlclient

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/agent/maintenance"
)

type commandCompletion struct {
	result   *controlv1.NodeCommandResult
	finalize func()
	release  func()
}

type uninstallReconciler interface {
	Purge(context.Context, string) error
}

func (r *Runner) startCommand(parent context.Context, command *controlv1.NodeCommand, results chan<- commandCompletion) error {
	if command == nil || command.RequestId == "" || len(command.RequestId) > 128 {
		return errors.New("controller node command identity is invalid")
	}
	if command.Kind == controlv1.NodeCommandKind_NODE_COMMAND_KIND_UNSPECIFIED || command.DeadlineUnix <= 0 {
		return errors.New("controller node command kind or deadline is invalid")
	}
	deadline := time.Unix(command.DeadlineUnix, 0).UTC()
	now := r.now().UTC()
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) {
		return errors.New("controller node command deadline is invalid")
	}

	r.commandMu.Lock()
	if r.commandActive {
		r.commandMu.Unlock()
		results <- commandCompletion{result: commandFailure(command, "agent_busy", "节点正在执行另一个操作", r.now())}
		return nil
	}
	r.commandActive = true
	r.commandKind = command.Kind
	r.commandMu.Unlock()

	go func() {
		release := func() {
			r.commandMu.Lock()
			r.commandActive = false
			r.commandKind = controlv1.NodeCommandKind_NODE_COMMAND_KIND_UNSPECIFIED
			r.commandMu.Unlock()
		}
		ctx, cancel := context.WithDeadline(parent, deadline)
		defer cancel()
		completion := r.executeCommand(ctx, command)
		completion.release = release
		select {
		case results <- completion:
		case <-parent.Done():
			if completion.finalize != nil {
				completion.finalize()
			}
			release()
		}
	}()
	return nil
}

func (r *Runner) executeCommand(ctx context.Context, command *controlv1.NodeCommand) commandCompletion {
	switch command.Kind {
	case controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK:
		return r.executeTCPCheck(ctx, command)
	case controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UPGRADE:
		return r.executeUpgrade(ctx, command)
	case controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UNINSTALL:
		return r.executeUninstall(ctx, command)
	default:
		return commandCompletion{result: commandFailure(command, "unsupported_command", "当前 Agent 不支持这个操作", r.now())}
	}
}

func (r *Runner) executeTCPCheck(ctx context.Context, command *controlv1.NodeCommand) commandCompletion {
	address, err := netip.ParseAddr(strings.TrimSpace(command.Address))
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || command.Port == 0 || command.Port > math.MaxUint16 {
		return commandCompletion{result: commandFailure(command, "invalid_target", "TCP 检查目标无效", r.now())}
	}
	startedAt := time.Now()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), fmt.Sprint(command.Port)))
	if err != nil {
		code, message := tcpCheckError(err)
		return commandCompletion{result: commandFailure(command, code, message, r.now())}
	}
	if err := connection.Close(); err != nil {
		return commandCompletion{result: commandFailure(command, "connection_close_failed", "TCP 已连接，但关闭检查连接失败", r.now())}
	}
	result := commandSuccess(command, r.now())
	latency := time.Since(startedAt).Microseconds()
	if latency < 1 {
		latency = 1
	}
	result.LatencyMicros = uint64(latency)
	return commandCompletion{result: result}
}

func (r *Runner) executeUpgrade(ctx context.Context, command *controlv1.NodeCommand) commandCompletion {
	if r.config.StateDirectory != maintenance.DefaultStateDirectory {
		return commandCompletion{result: commandFailure(command, "nonstandard_installation", "非标准安装路径暂不支持网页升级", r.now())}
	}
	stage, err := maintenance.StageUpgrade(ctx, command.ReleaseUrl, command.ChecksumUrl, r.config.StateDirectory)
	if err != nil {
		return commandCompletion{result: commandFailure(command, "upgrade_verification_failed", "下载或校验新版 Agent 失败", r.now())}
	}
	request := maintenance.Request{
		Version: maintenance.RequestVersion, Action: maintenance.ActionUpgrade, StagedBinary: stage.Path,
		DestinationExecutable: maintenance.DefaultExecutable, AgentUnitPath: maintenance.DefaultAgentUnitPath,
		MaintenanceUnitPath: maintenance.DefaultMaintenanceUnitPath, IdentityDirectory: maintenance.DefaultIdentityDirectory,
		StateDirectory: maintenance.DefaultStateDirectory,
	}
	if _, err := maintenance.WriteRequest(request); err != nil {
		return commandCompletion{result: commandFailure(command, "upgrade_prepare_failed", "准备新版 Agent 失败", r.now())}
	}
	if err := maintenance.Start(ctx, r.config.SystemctlPath); err != nil {
		return commandCompletion{result: commandFailure(command, "upgrade_apply_failed", "安装新版 Agent 失败", r.now())}
	}
	return commandCompletion{
		result: commandSuccess(command, r.now()),
		finalize: func() {
			if err := maintenance.RestartAgent(r.config.SystemctlPath); err != nil {
				r.logger.Error("restart upgraded Agent", "error", err)
			}
		},
	}
}

func (r *Runner) executeUninstall(ctx context.Context, command *controlv1.NodeCommand) commandCompletion {
	if r.config.StateDirectory != maintenance.DefaultStateDirectory {
		return commandCompletion{result: commandFailure(command, "nonstandard_installation", "非标准安装路径暂不支持网页卸载", r.now())}
	}
	record, err := r.store.Load()
	if err != nil {
		return commandCompletion{result: commandFailure(command, "state_read_failed", "无法读取节点当前配置", r.now())}
	}
	if record.Pending != nil {
		return commandCompletion{result: commandFailure(command, "configuration_busy", "节点仍有配置正在同步", r.now())}
	}
	if record.Applied != nil && len(record.Applied.Desired.Forwards) != 0 {
		return commandCompletion{result: commandFailure(command, "node_in_use", "节点仍承载转发，不能卸载", r.now())}
	}
	request := maintenance.Request{
		Version: maintenance.RequestVersion, Action: maintenance.ActionUninstall,
		DestinationExecutable: maintenance.DefaultExecutable, AgentUnitPath: maintenance.DefaultAgentUnitPath,
		MaintenanceUnitPath: maintenance.DefaultMaintenanceUnitPath, IdentityDirectory: maintenance.DefaultIdentityDirectory,
		StateDirectory: maintenance.DefaultStateDirectory,
	}
	requestPath, err := maintenance.WriteRequest(request)
	if err != nil {
		return commandCompletion{result: commandFailure(command, "uninstall_prepare_failed", "准备卸载失败", r.now())}
	}
	purger, ok := r.reconciler.(uninstallReconciler)
	if !ok {
		_ = os.Remove(requestPath)
		return commandCompletion{result: commandFailure(command, "uninstall_not_supported", "当前 Agent 无法安全清理节点资源", r.now())}
	}
	if err := purger.Purge(ctx, r.config.NodeID); err != nil {
		_ = os.Remove(requestPath)
		return commandCompletion{result: commandFailure(command, "dataplane_cleanup_failed", "清理节点转发资源失败，已取消卸载", r.now())}
	}
	if err := maintenance.Start(ctx, r.config.SystemctlPath); err != nil {
		_ = os.Remove(requestPath)
		return commandCompletion{result: commandFailure(command, "uninstall_apply_failed", "删除 Agent 安装文件失败", r.now())}
	}
	return commandCompletion{
		result: commandSuccess(command, r.now()),
		finalize: func() {
			if err := os.RemoveAll(r.config.StateDirectory); err != nil {
				r.logger.Error("remove uninstalled Agent state", "error", err)
			}
			if err := maintenance.StopAgent(r.config.SystemctlPath); err != nil {
				r.logger.Error("stop uninstalled Agent", "error", err)
			}
		},
	}
}

func commandSuccess(command *controlv1.NodeCommand, now time.Time) *controlv1.NodeCommandResult {
	return &controlv1.NodeCommandResult{
		RequestId: command.RequestId, Kind: command.Kind, Success: true, CompletedAtUnix: now.UTC().Unix(),
	}
}

func commandFailure(command *controlv1.NodeCommand, code, message string, now time.Time) *controlv1.NodeCommandResult {
	if len(message) > 1024 {
		message = message[:1024]
	}
	return &controlv1.NodeCommandResult{
		RequestId: command.RequestId, Kind: command.Kind, Success: false,
		ErrorCode: code, ErrorMessage: message, CompletedAtUnix: now.UTC().Unix(),
	}
}

func tcpCheckError(err error) (string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "TCP 连接超时"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused", "目标端口拒绝连接"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "network_unreachable", "目标网络不可达"
	default:
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return "timeout", "TCP 连接超时"
		}
		return "connection_failed", "无法连接目标 TCP 端口"
	}
}
