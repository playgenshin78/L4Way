package management

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/cluster"
	controllercontrol "flux.local/flux/internal/controller/control"
	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/spec"
	"flux.local/flux/internal/targetdns"
)

const (
	sessionCookieName = "flux_session"
	csrfCookieName    = "flux_csrf"
	csrfHeaderName    = "X-CSRF-Token"
	maxRequestBytes   = 1 << 20
	loginWindowTTL    = 15 * time.Minute
	maxLoginIPWindows = 4096
)

type Repository interface {
	AccountByUsername(context.Context, string) (iam.Account, error)
	TenantAccountByTenantID(context.Context, string) (iam.Account, error)
	ReplaceAccountPassword(context.Context, string, string, uint64) (iam.Account, error)
	ManagementSession(context.Context, string, time.Time) (iam.Session, error)
	CreateManagementSession(context.Context, string, time.Duration, string, string) (string, string, iam.Session, error)
	RevokeManagementSession(context.Context, string, time.Time) error
	RecordLoginFailure(context.Context, string, time.Time) error
	RecordLoginSuccess(context.Context, string, time.Time) error
	CreateTenant(context.Context, store.TenantCreate) (iam.Tenant, iam.Account, iam.Policy, error)
	TenantByID(context.Context, string) (iam.Tenant, error)
	ListTenants(context.Context, int, int) ([]iam.Tenant, error)
	UpdateTenant(context.Context, string, string, iam.Status, *time.Time, uint64) (iam.Tenant, error)
	TenantPolicy(context.Context, string) (iam.Policy, error)
	UpdateTenantPolicy(context.Context, iam.Policy) (iam.Policy, error)
	RecordManagementAudit(context.Context, iam.AuditEvent) error
	ListManagementAudit(context.Context, int, int) ([]iam.AuditEvent, error)
	ActiveClusterPlan(context.Context, string) (store.ActiveClusterPlan, error)
	ApplyClusterPlan(context.Context, cluster.Plan, string) (store.ClusterApplyResult, error)
	LatestSnapshot(context.Context, string) (store.SnapshotRecord, bool, error)
	CreateEnrollmentToken(context.Context, string, time.Duration) (string, time.Time, error)
	ListNodes(context.Context, int, int) ([]store.NodeSummary, error)
	DeletePendingNode(context.Context, string) error
	RevokeNode(context.Context, string, time.Time) error
	ReadUsageSummary(context.Context, string, time.Time, time.Time) (store.UsageSummary, error)
}

type NodeCommander interface {
	Dispatch(context.Context, string, controllercontrol.CommandRequest) (*controlv1.NodeCommandResult, error)
}

type Config struct {
	SessionTTL              time.Duration
	CookieSecure            bool
	PlanID                  string
	ControllerPublicKey     string
	PublicEnrollmentAddress string
	PublicControlAddress    string
	NodeInstallerURL        string
	NodeReleaseURL          string
	NodeOfflineAfter        time.Duration
	DatabasePath            string
	BackupDirectory         string
	Backup                  func(context.Context, string) error
	ControllerVersion       string
	AgentMinVersion         string
	StartedAt               time.Time
	Now                     func() time.Time
	ResolveTargetIPv4       func(context.Context, string) (netip.Addr, error)
	TargetResolveTimeout    time.Duration
	NodeCommands            NodeCommander
}

type Server struct {
	repository Repository
	logger     *slog.Logger
	config     Config
	handler    http.Handler
	dummyHash  string
	limiter    loginLimiter
	loginSlots chan struct{}
	// Plan-changing HTTP operations may run concurrently, but a node uninstall
	// takes the exclusive lock so no forward can select the node between its
	// final safety check and identity revocation.
	planMutationMu sync.RWMutex
}

type tenantView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Username        string     `json:"username"`
	DisplayName     string     `json:"display_name"`
	Status          iam.Status `json:"status"`
	ForwardsCount   uint32     `json:"forwards_count"`
	ExpiresAt       *time.Time `json:"expires_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	ResourceVersion uint64     `json:"resource_version"`
}

type contextKey int

const sessionContextKey contextKey = iota

func New(repository Repository, logger *slog.Logger, config Config) (*Server, error) {
	if repository == nil {
		return nil, errors.New("management repository is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = 24 * time.Hour
	}
	if config.SessionTTL < 5*time.Minute || config.SessionTTL > 30*24*time.Hour {
		return nil, errors.New("management session TTL must be between five minutes and 30 days")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ResolveTargetIPv4 == nil {
		config.ResolveTargetIPv4 = targetdns.LookupIPv4
	}
	if config.TargetResolveTimeout == 0 {
		config.TargetResolveTimeout = 3 * time.Second
	}
	if config.TargetResolveTimeout < 100*time.Millisecond || config.TargetResolveTimeout > 30*time.Second {
		return nil, errors.New("target DNS timeout must be between 100 milliseconds and 30 seconds")
	}
	if config.StartedAt.IsZero() {
		config.StartedAt = config.Now().UTC()
	}
	if strings.TrimSpace(config.ControllerVersion) == "" {
		config.ControllerVersion = "dev"
	}
	if strings.TrimSpace(config.AgentMinVersion) == "" {
		config.AgentMinVersion = "dev"
	}
	if config.NodeOfflineAfter == 0 {
		config.NodeOfflineAfter = 95 * time.Second
	}
	if config.NodeOfflineAfter < 10*time.Second || config.NodeOfflineAfter > 30*time.Minute {
		return nil, errors.New("node offline threshold must be between 10 seconds and 30 minutes")
	}
	if strings.TrimSpace(config.PlanID) == "" {
		config.PlanID = "default"
	}
	if err := spec.ValidateIdentifier("management plan_id", config.PlanID); err != nil {
		return nil, err
	}
	bootstrapConfigured := strings.TrimSpace(config.PublicEnrollmentAddress) != "" || strings.TrimSpace(config.PublicControlAddress) != ""
	if bootstrapConfigured && (!validBootstrapAddress(config.PublicEnrollmentAddress) || !validBootstrapAddress(config.PublicControlAddress) || strings.TrimSpace(config.ControllerPublicKey) == "") {
		return nil, errors.New("node install commands require Controller public key plus public enrollment and control host:port addresses")
	}
	nodeDownloadConfigured := strings.TrimSpace(config.NodeInstallerURL) != "" || strings.TrimSpace(config.NodeReleaseURL) != ""
	if nodeDownloadConfigured && (!validHTTPSDownloadURL(config.NodeInstallerURL) || !validHTTPSDownloadURL(config.NodeReleaseURL)) {
		return nil, errors.New("one-click node installation requires HTTPS installer and release URLs")
	}
	dummyHash, err := iam.HashPassword("flux-dummy-password-never-used")
	if err != nil {
		return nil, err
	}
	server := &Server{repository: repository, logger: logger, config: config, dummyHash: dummyHash, loginSlots: make(chan struct{}, 4)}
	server.handler = server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.Handle("POST /api/v1/auth/logout", s.authenticated(http.HandlerFunc(s.handleLogout), false, true))
	mux.Handle("GET /api/v1/auth/me", s.authenticated(http.HandlerFunc(s.handleMe), false, false))
	mux.Handle("POST /api/v1/auth/password", s.authenticated(http.HandlerFunc(s.handleChangePassword), false, true))
	mux.Handle("GET /api/v1/tenants", s.authenticated(http.HandlerFunc(s.handleListTenants), true, false))
	mux.Handle("POST /api/v1/tenants", s.authenticated(http.HandlerFunc(s.handleCreateTenant), true, true))
	mux.Handle("GET /api/v1/tenants/{tenantID}", s.authenticated(http.HandlerFunc(s.handleGetTenant), false, false))
	mux.Handle("PATCH /api/v1/tenants/{tenantID}", s.authenticated(http.HandlerFunc(s.handleUpdateTenant), true, true))
	mux.Handle("POST /api/v1/tenants/{tenantID}/password-reset", s.authenticated(http.HandlerFunc(s.handleResetTenantPassword), true, true))
	mux.Handle("GET /api/v1/tenants/{tenantID}/policy", s.authenticated(http.HandlerFunc(s.handleGetPolicy), false, false))
	mux.Handle("PATCH /api/v1/tenants/{tenantID}/policy", s.authenticated(http.HandlerFunc(s.handleUpdatePolicy), true, true))
	mux.Handle("GET /api/v1/audit", s.authenticated(http.HandlerFunc(s.handleListAudit), true, false))
	mux.Handle("GET /api/v1/forwards", s.authenticated(http.HandlerFunc(s.handleListForwards), false, false))
	mux.Handle("POST /api/v1/forwards", s.authenticated(http.HandlerFunc(s.handleCreateForward), false, true))
	mux.Handle("GET /api/v1/forwards/{forwardID}", s.authenticated(http.HandlerFunc(s.handleGetForward), false, false))
	mux.Handle("PATCH /api/v1/forwards/{forwardID}", s.authenticated(http.HandlerFunc(s.handleUpdateForward), false, true))
	mux.Handle("DELETE /api/v1/forwards/{forwardID}", s.authenticated(http.HandlerFunc(s.handleDeleteForward), false, true))
	mux.Handle("POST /api/v1/forwards/{forwardID}/tcp-check", s.authenticated(http.HandlerFunc(s.handleForwardTCPCheck), false, true))
	mux.Handle("POST /api/v1/nodes/install-command", s.authenticated(http.HandlerFunc(s.handleNodeInstallCommand), true, true))
	mux.Handle("GET /api/v1/nodes", s.authenticated(http.HandlerFunc(s.handleListNodes), false, false))
	mux.Handle("PATCH /api/v1/nodes/{nodeID}/protocol-blocks", s.authenticated(http.HandlerFunc(s.handleUpdateNodeProtocolBlocks), true, true))
	mux.Handle("DELETE /api/v1/nodes/{nodeID}", s.authenticated(http.HandlerFunc(s.handleDeleteNode), true, true))
	mux.Handle("POST /api/v1/nodes/{nodeID}/revoke", s.authenticated(http.HandlerFunc(s.handleRevokeNode), true, true))
	mux.Handle("POST /api/v1/nodes/{nodeID}/upgrade", s.authenticated(http.HandlerFunc(s.handleUpgradeNode), true, true))
	mux.Handle("POST /api/v1/nodes/{nodeID}/uninstall", s.authenticated(http.HandlerFunc(s.handleUninstallNode), true, true))
	mux.Handle("GET /api/v1/usage", s.authenticated(http.HandlerFunc(s.handleUsage), false, false))
	mux.Handle("GET /api/v1/system/status", s.authenticated(http.HandlerFunc(s.handleSystemStatus), true, false))
	mux.Handle("POST /api/v1/system/backup", s.authenticated(http.HandlerFunc(s.handleSystemBackup), true, true))
	mux.Handle("POST /api/v1/system/backup/download", s.authenticated(http.HandlerFunc(s.handleSystemBackupDownload), true, true))
	return securityHeaders(mux)
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	remoteIP := sourceIP(request)
	if !s.limiter.allow(remoteIP, s.config.Now().UTC()) {
		writeError(writer, http.StatusTooManyRequests, "login_rate_limited", "too many login attempts")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		writeError(writer, http.StatusTooManyRequests, "login_busy", "too many login operations are in progress")
		return
	}
	now := s.config.Now().UTC()
	account, lookupErr := s.repository.AccountByUsername(request.Context(), input.Username)
	passwordOK := false
	passwordFormatOK := len(input.Password) >= 1 && len(input.Password) <= 128 && !strings.ContainsRune(input.Password, 0)
	if lookupErr == nil && passwordFormatOK {
		passwordOK = iam.VerifyPassword(account.PasswordHash, input.Password)
	} else {
		dummyPassword := input.Password
		if !passwordFormatOK {
			dummyPassword = "invalid-password-shape"
		}
		_ = iam.VerifyPassword(s.dummyHash, dummyPassword)
	}
	if lookupErr != nil || !passwordOK || account.Available(now) != nil {
		if lookupErr == nil && !passwordOK {
			_ = s.repository.RecordLoginFailure(request.Context(), account.ID, now)
		}
		s.audit(request.Context(), iam.AuditEvent{ActorUsername: normalizedAuditUsername(input.Username), Action: "auth.login", ResourceType: "session", Outcome: "denied", SourceIP: remoteIP})
		writeError(writer, http.StatusUnauthorized, "invalid_credentials", "username or password is invalid")
		return
	}
	if err := s.repository.RecordLoginSuccess(request.Context(), account.ID, now); err != nil {
		s.logger.Error("record management login", "account_id", account.ID, "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "login could not be completed")
		return
	}
	token, csrf, session, err := s.repository.CreateManagementSession(request.Context(), account.ID, s.config.SessionTTL, remoteIP, request.UserAgent())
	if err != nil {
		s.logger.Error("create management session", "account_id", account.ID, "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "login could not be completed")
		return
	}
	s.limiter.reset(remoteIP)
	s.setSessionCookies(writer, token, csrf, session.ExpiresAt)
	s.audit(request.Context(), iam.AuditEvent{ActorAccountID: account.ID, ActorUsername: account.Username, ActorRole: account.Role, TenantID: account.TenantID, Action: "auth.login", ResourceType: "session", Outcome: "success", SourceIP: remoteIP})
	writeData(writer, http.StatusOK, map[string]any{"account": publicAccount(session.Account), "csrf_token": csrf, "expires_at": session.ExpiresAt})
}

func (s *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	session := sessionFromContext(request.Context())
	if cookie, err := request.Cookie(sessionCookieName); err == nil {
		_ = s.repository.RevokeManagementSession(request.Context(), cookie.Value, s.config.Now().UTC())
	}
	s.clearSessionCookies(writer)
	s.auditSession(request.Context(), request, session, "auth.logout", "session", "", "success", nil)
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(writer http.ResponseWriter, request *http.Request) {
	session := sessionFromContext(request.Context())
	csrf := ""
	if cookie, err := request.Cookie(csrfCookieName); err == nil {
		csrf = cookie.Value
	}
	writeData(writer, http.StatusOK, map[string]any{"account": publicAccount(session.Account), "csrf_token": csrf, "expires_at": session.ExpiresAt})
}

func (s *Server) handleListTenants(writer http.ResponseWriter, request *http.Request) {
	limit, offset := pagination(request)
	tenants, err := s.repository.ListTenants(request.Context(), limit, offset)
	if err != nil {
		s.internalError(writer, "list tenants", err)
		return
	}
	counts := s.tenantForwardCounts(request.Context())
	items := make([]tenantView, 0, len(tenants))
	for _, tenant := range tenants {
		view, err := s.viewTenant(request.Context(), tenant, counts[tenant.ID])
		if err != nil {
			s.internalError(writer, "render tenant", err)
			return
		}
		items = append(items, view)
	}
	writeData(writer, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset, "total": len(items)})
}

func (s *Server) viewTenant(ctx context.Context, tenant iam.Tenant, forwardsCount uint32) (tenantView, error) {
	account, err := s.repository.TenantAccountByTenantID(ctx, tenant.ID)
	if err != nil {
		return tenantView{}, err
	}
	return tenantViewFrom(tenant, account, forwardsCount), nil
}

func tenantViewFrom(tenant iam.Tenant, account iam.Account, forwardsCount uint32) tenantView {
	return tenantView{
		ID: tenant.ID, Name: tenant.Name, Username: account.Username, DisplayName: account.DisplayName, Status: tenant.Status,
		ForwardsCount: forwardsCount, ExpiresAt: tenant.ExpiresAt, CreatedAt: tenant.CreatedAt,
		UpdatedAt: tenant.UpdatedAt, ResourceVersion: tenant.ResourceVersion,
	}
}

func (s *Server) tenantForwardCounts(ctx context.Context) map[string]uint32 {
	counts := make(map[string]uint32)
	record, err := s.repository.ActiveClusterPlan(ctx, s.config.PlanID)
	if err != nil {
		return counts
	}
	for _, forward := range record.Plan.Forwards {
		if forward.UserID != "owner" && forward.Lifecycle != spec.LifecycleForceDeleting {
			counts[forward.UserID]++
		}
	}
	return counts
}

func (s *Server) handleCreateTenant(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		ID          string      `json:"id"`
		Name        string      `json:"name"`
		Username    string      `json:"username"`
		DisplayName string      `json:"display_name"`
		Password    string      `json:"password"`
		ExpiresAt   *time.Time  `json:"expires_at"`
		Policy      *iam.Policy `json:"policy"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	passwordHash, err := iam.HashPassword(input.Password)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		input.Name = input.DisplayName
	}
	tenant, account, policy, err := s.repository.CreateTenant(request.Context(), store.TenantCreate{
		ID: input.ID, Name: input.Name, Username: input.Username, DisplayName: input.DisplayName,
		PasswordHash: passwordHash, ExpiresAt: input.ExpiresAt, InitialPolicy: input.Policy,
	})
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	s.auditSession(request.Context(), request, sessionFromContext(request.Context()), "tenant.create", "tenant", tenant.ID, "success", map[string]any{"username": account.Username})
	view := tenantViewFrom(tenant, account, 0)
	writeData(writer, http.StatusCreated, map[string]any{"tenant": view, "account": publicAccount(account), "policy": policy})
}

func (s *Server) handleGetTenant(writer http.ResponseWriter, request *http.Request) {
	session := sessionFromContext(request.Context())
	tenantID := request.PathValue("tenantID")
	if !canAccessTenant(session.Account, tenantID) {
		writeError(writer, http.StatusForbidden, "forbidden", "tenant is outside the authenticated scope")
		return
	}
	tenant, err := s.repository.TenantByID(request.Context(), tenantID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	account, err := s.repository.TenantAccountByTenantID(request.Context(), tenantID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	writeData(writer, http.StatusOK, tenantViewFrom(tenant, account, s.tenantForwardCounts(request.Context())[tenantID]))
}

func (s *Server) handleUpdateTenant(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Name            *string         `json:"name"`
		Status          *iam.Status     `json:"status"`
		ExpiresAt       json.RawMessage `json:"expires_at"`
		ResourceVersion uint64          `json:"resource_version"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenantID := request.PathValue("tenantID")
	current, err := s.repository.TenantByID(request.Context(), tenantID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	name := current.Name
	if input.Name != nil {
		name = *input.Name
	}
	status := current.Status
	if input.Status != nil {
		status = *input.Status
	}
	expiresAt := current.ExpiresAt
	if input.ExpiresAt != nil {
		if string(input.ExpiresAt) == "null" {
			expiresAt = nil
		} else {
			var value time.Time
			if err := json.Unmarshal(input.ExpiresAt, &value); err != nil {
				writeError(writer, http.StatusBadRequest, "invalid_request", "expires_at must be an RFC3339 timestamp or null")
				return
			}
			expiresAt = &value
		}
	}
	tenant, err := s.repository.UpdateTenant(request.Context(), tenantID, name, status, expiresAt, input.ResourceVersion)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	s.auditSession(request.Context(), request, sessionFromContext(request.Context()), "tenant.update", "tenant", tenantID, "success", map[string]any{"status": tenant.Status})
	account, err := s.repository.TenantAccountByTenantID(request.Context(), tenantID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	writeData(writer, http.StatusOK, tenantViewFrom(tenant, account, s.tenantForwardCounts(request.Context())[tenantID]))
}

func (s *Server) handleGetPolicy(writer http.ResponseWriter, request *http.Request) {
	session := sessionFromContext(request.Context())
	tenantID := request.PathValue("tenantID")
	if !canAccessTenant(session.Account, tenantID) {
		writeError(writer, http.StatusForbidden, "forbidden", "tenant policy is outside the authenticated scope")
		return
	}
	policy, err := s.repository.TenantPolicy(request.Context(), tenantID)
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	writeData(writer, http.StatusOK, policy)
}

func (s *Server) handleUpdatePolicy(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		AllowedIngressNodes []string        `json:"allowed_ingress_nodes"`
		AllowedExitNodes    []string        `json:"allowed_exit_nodes"`
		AllowedListenIPs    []string        `json:"allowed_listen_ips"`
		AllowedPortRanges   []iam.PortRange `json:"allowed_port_ranges"`
		AllowedProtocols    []spec.Protocol `json:"allowed_protocols"`
		AllowViaExit        bool            `json:"allow_via_exit"`
		MaxForwards         uint32          `json:"max_forwards"`
		IngressRateLimitBPS uint64          `json:"ingress_rate_limit_bps"`
		EgressRateLimitBPS  uint64          `json:"egress_rate_limit_bps"`
		TrafficQuotaBytes   uint64          `json:"traffic_quota_bytes"`
		AllowedTargetCIDRs  []string        `json:"allowed_target_cidrs"`
		DeniedTargetCIDRs   []string        `json:"denied_target_cidrs"`
		ResourceVersion     uint64          `json:"resource_version"`
	}
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenantID := request.PathValue("tenantID")
	policy, err := s.repository.UpdateTenantPolicy(request.Context(), iam.Policy{
		TenantID: tenantID, AllowedIngressNodes: input.AllowedIngressNodes, AllowedExitNodes: input.AllowedExitNodes,
		AllowedListenIPs: input.AllowedListenIPs, AllowedPortRanges: input.AllowedPortRanges, AllowedProtocols: input.AllowedProtocols,
		AllowViaExit: input.AllowViaExit, MaxForwards: input.MaxForwards, IngressRateLimitBPS: input.IngressRateLimitBPS,
		EgressRateLimitBPS: input.EgressRateLimitBPS, TrafficQuotaBytes: input.TrafficQuotaBytes,
		AllowedTargetCIDRs: input.AllowedTargetCIDRs, DeniedTargetCIDRs: input.DeniedTargetCIDRs,
		ResourceVersion: input.ResourceVersion,
	})
	if err != nil {
		s.writeRepositoryError(writer, err)
		return
	}
	s.auditSession(request.Context(), request, sessionFromContext(request.Context()), "tenant.policy.update", "tenant_policy", tenantID, "success", map[string]any{"resource_version": policy.ResourceVersion})
	writeData(writer, http.StatusOK, policy)
}

func (s *Server) handleListAudit(writer http.ResponseWriter, request *http.Request) {
	limit, offset := pagination(request)
	events, err := s.repository.ListManagementAudit(request.Context(), limit, offset)
	if err != nil {
		s.internalError(writer, "list management audit", err)
		return
	}
	writeData(writer, http.StatusOK, map[string]any{"items": events, "limit": limit, "offset": offset})
}

func (s *Server) authenticated(next http.Handler, ownerOnly, requireCSRF bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(writer, http.StatusUnauthorized, "unauthenticated", "authentication is required")
			return
		}
		session, err := s.repository.ManagementSession(request.Context(), cookie.Value, s.config.Now().UTC())
		if err != nil {
			s.clearSessionCookies(writer)
			writeError(writer, http.StatusUnauthorized, "unauthenticated", "session is invalid or expired")
			return
		}
		if ownerOnly && session.Account.Role != iam.RoleOwner {
			s.auditSession(request.Context(), request, session, "authorization.denied", "route", request.URL.Path, "denied", nil)
			writeError(writer, http.StatusForbidden, "forbidden", "Owner permission is required")
			return
		}
		if requireCSRF && !csrfValid(request, session.CSRFHash) {
			s.auditSession(request.Context(), request, session, "csrf.denied", "route", request.URL.Path, "denied", nil)
			writeError(writer, http.StatusForbidden, "invalid_csrf", "CSRF token is invalid")
			return
		}
		ctx := context.WithValue(request.Context(), sessionContextKey, session)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func csrfValid(request *http.Request, expected [32]byte) bool {
	header := request.Header.Get(csrfHeaderName)
	cookie, err := request.Cookie(csrfCookieName)
	if err != nil || header == "" || len(header) > 128 || subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) != 1 {
		return false
	}
	actual := iam.HashSecret(header)
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func (s *Server) setSessionCookies(writer http.ResponseWriter, token, csrf string, expiresAt time.Time) {
	maxAge := int(expiresAt.Sub(s.config.Now().UTC()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/api/", Expires: expiresAt, MaxAge: maxAge, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(writer, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/", Expires: expiresAt, MaxAge: maxAge, HttpOnly: false, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearSessionCookies(writer http.ResponseWriter) {
	for _, cookie := range []*http.Cookie{
		{Name: sessionCookieName, Path: "/api/", HttpOnly: true},
		{Name: csrfCookieName, Path: "/"},
	} {
		cookie.Value = ""
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
		cookie.Secure = s.config.CookieSecure
		cookie.SameSite = http.SameSiteStrictMode
		http.SetCookie(writer, cookie)
	}
}

func (s *Server) auditSession(ctx context.Context, request *http.Request, session iam.Session, action, resourceType, resourceID, outcome string, detail map[string]any) {
	s.audit(ctx, iam.AuditEvent{ActorAccountID: session.Account.ID, ActorUsername: session.Account.Username, ActorRole: session.Account.Role,
		TenantID: session.Account.TenantID, Action: action, ResourceType: resourceType, ResourceID: resourceID, Outcome: outcome,
		SourceIP: sourceIP(request), Detail: detail})
}

func (s *Server) audit(ctx context.Context, event iam.AuditEvent) {
	if err := s.repository.RecordManagementAudit(ctx, event); err != nil {
		s.logger.Error("record management audit", "action", event.Action, "error", err)
	}
}

func (s *Server) writeRepositoryError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, iam.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, store.ErrNodeNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "node was not found")
	case errors.Is(err, store.ErrNodeDeletionConflict):
		writeError(writer, http.StatusConflict, "node_delete_conflict", "only a never-enrolled pending node can be deleted")
	case errors.Is(err, store.ErrClusterPlanNotFound):
		writeError(writer, http.StatusConflict, "cluster_plan_not_configured", "the management cluster plan has not been configured")
	case errors.Is(err, store.ErrNodeAlreadyEnrolled):
		writeError(writer, http.StatusConflict, "node_already_enrolled", "node already has an active identity")
	case errors.Is(err, store.ErrNodeRevoked):
		writeError(writer, http.StatusConflict, "node_revoked", "node identity has been permanently revoked")
	case errors.Is(err, iam.ErrConflict), errors.Is(err, store.ErrPlanRevisionConflict), errors.Is(err, store.ErrRolloutInProgress),
		errors.Is(err, store.ErrManagementConflict):
		writeError(writer, http.StatusConflict, "resource_conflict", "resource changed; reload and retry")
	case errors.Is(err, iam.ErrForbidden):
		writeError(writer, http.StatusForbidden, "forbidden", iam.PolicyReason(err))
	default:
		if isInputError(err) {
			writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		s.internalError(writer, "management repository", err)
	}
}

func (s *Server) internalError(writer http.ResponseWriter, operation string, err error) {
	s.logger.Error(operation, "error", err)
	writeError(writer, http.StatusInternalServerError, "internal_error", "request could not be completed")
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("request body is invalid: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

func writeData(writer http.ResponseWriter, status int, data any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"data": data})
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func publicAccount(account iam.Account) iam.Account {
	account.PasswordHash = ""
	account.FailedLoginCount = 0
	account.LockedUntil = nil
	return account
}

func sessionFromContext(ctx context.Context) iam.Session {
	session, _ := ctx.Value(sessionContextKey).(iam.Session)
	return session
}

func canAccessTenant(account iam.Account, tenantID string) bool {
	return account.Role == iam.RoleOwner || account.Role == iam.RoleTenant && account.TenantID == tenantID
}

func pagination(request *http.Request) (int, int) {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(request.URL.Query().Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func sourceIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	remoteIP := net.ParseIP(strings.TrimSpace(host))
	if remoteIP != nil && remoteIP.IsLoopback() {
		for _, candidate := range []string{
			strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0]),
			strings.TrimSpace(request.Header.Get("X-Real-IP")),
		} {
			if parsed := net.ParseIP(candidate); parsed != nil {
				return parsed.String()
			}
		}
	}
	if remoteIP != nil {
		return remoteIP.String()
	}
	return host
}

func normalizedAuditUsername(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}

func isInputError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "invalid") || strings.Contains(message, "must") || strings.Contains(message, "required") || strings.Contains(message, "expiry") || strings.Contains(message, "exceeds") || strings.Contains(message, "duplicate")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(writer, request)
	})
}

type loginLimiter struct {
	mu        sync.Mutex
	attempts  map[string]loginWindow
	lastSweep time.Time
}

type loginWindow struct {
	started time.Time
	count   int
}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.attempts == nil {
		l.attempts = make(map[string]loginWindow)
	}
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute || len(l.attempts) >= maxLoginIPWindows {
		for candidate, window := range l.attempts {
			if now.Sub(window.started) >= loginWindowTTL {
				delete(l.attempts, candidate)
			}
		}
		l.lastSweep = now
	}
	window, exists := l.attempts[key]
	if !exists && len(l.attempts) >= maxLoginIPWindows {
		return false
	}
	if window.started.IsZero() || now.Sub(window.started) >= loginWindowTTL {
		l.attempts[key] = loginWindow{started: now, count: 1}
		return true
	}
	if window.count >= 20 {
		return false
	}
	window.count++
	l.attempts[key] = window
	return true
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
