package iam

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"flux.local/flux/internal/spec"
)

type Role string

const (
	RoleOwner  Role = "owner"
	RoleTenant Role = "tenant"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

var (
	ErrUnauthenticated = errors.New("authentication failed")
	ErrForbidden       = errors.New("operation is not permitted")
	ErrConflict        = errors.New("resource version conflict")
	ErrNotFound        = errors.New("identity resource not found")
)

type Tenant struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Status          Status     `json:"status"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ResourceVersion uint64     `json:"resource_version"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Account struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id,omitempty"`
	Username         string     `json:"username"`
	DisplayName      string     `json:"display_name"`
	Role             Role       `json:"role"`
	Status           Status     `json:"status"`
	PasswordHash     string     `json:"-"`
	FailedLoginCount uint32     `json:"-"`
	LockedUntil      *time.Time `json:"-"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ResourceVersion  uint64     `json:"resource_version"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func (a Account) Available(now time.Time) error {
	if a.Status != StatusActive {
		return ErrUnauthenticated
	}
	if a.ExpiresAt != nil && !now.Before(*a.ExpiresAt) {
		return ErrUnauthenticated
	}
	if a.LockedUntil != nil && now.Before(*a.LockedUntil) {
		return ErrUnauthenticated
	}
	return nil
}

type PortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type Policy struct {
	TenantID            string          `json:"tenant_id"`
	AllowedIngressNodes []string        `json:"allowed_ingress_nodes"`
	AllowedExitNodes    []string        `json:"allowed_exit_nodes"`
	AllowedListenIPs    []string        `json:"allowed_listen_ips"`
	AllowedPortRanges   []PortRange     `json:"allowed_port_ranges"`
	AllowedProtocols    []spec.Protocol `json:"allowed_protocols"`
	AllowViaExit        bool            `json:"allow_via_exit"`
	MaxForwards         uint32          `json:"max_forwards"`
	IngressRateLimitBPS uint64          `json:"ingress_rate_limit_bps"`
	EgressRateLimitBPS  uint64          `json:"egress_rate_limit_bps"`
	TrafficQuotaBytes   uint64          `json:"traffic_quota_bytes"`
	AllowedTargetCIDRs  []string        `json:"allowed_target_cidrs"`
	DeniedTargetCIDRs   []string        `json:"denied_target_cidrs"`
	ResourceVersion     uint64          `json:"resource_version"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

func EmptyPolicy(tenantID string) Policy {
	return Policy{
		TenantID: tenantID, AllowedIngressNodes: []string{}, AllowedExitNodes: []string{},
		AllowedListenIPs: []string{}, AllowedPortRanges: []PortRange{}, AllowedProtocols: []spec.Protocol{},
		AllowedTargetCIDRs: []string{}, DeniedTargetCIDRs: []string{}, ResourceVersion: 1,
	}
}

type Session struct {
	Account   Account
	CSRFHash  [32]byte
	ExpiresAt time.Time
}

type AuditEvent struct {
	ID             int64          `json:"id"`
	ActorAccountID string         `json:"actor_account_id,omitempty"`
	ActorUsername  string         `json:"actor_username"`
	ActorRole      Role           `json:"actor_role,omitempty"`
	TenantID       string         `json:"tenant_id,omitempty"`
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     string         `json:"resource_id,omitempty"`
	Outcome        string         `json:"outcome"`
	SourceIP       string         `json:"source_ip,omitempty"`
	Detail         map[string]any `json:"detail"`
	CreatedAt      time.Time      `json:"created_at"`
}

func NormalizeUsername(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !usernamePattern.MatchString(value) {
		return "", errors.New("username must be 3-64 lowercase letters, digits, dots, underscores or hyphens")
	}
	return value, nil
}

func ValidateDisplayName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 128 {
		return "", errors.New("display name must be 1-128 bytes")
	}
	return value, nil
}

func ValidateTenantName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 128 {
		return "", errors.New("tenant name must be 1-128 bytes")
	}
	return value, nil
}

func ValidateInternalID(name, value string) error {
	return spec.ValidateIdentifier(name, value)
}

func NewID(prefix string) (string, error) {
	if prefix == "" || strings.ContainsAny(prefix, "_.:-") {
		return "", errors.New("identity ID prefix is invalid")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate identity ID: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(random), nil
}

func NewSecret() (string, [32]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate session secret: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(random)
	return raw, sha256.Sum256([]byte(raw)), nil
}

func HashSecret(raw string) [32]byte {
	return sha256.Sum256([]byte(raw))
}
