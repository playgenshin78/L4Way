package management

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"flux.local/flux/internal/controller/iam"
)

type usageSeriesPoint struct {
	Timestamp time.Time `json:"ts"`
	Bytes     uint64    `json:"bytes"`
}

type usageForwardView struct {
	ForwardID string `json:"forward_id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Bytes     uint64 `json:"bytes"`
}

func (s *Server) handleUsage(writer http.ResponseWriter, request *http.Request) {
	days := 30
	if raw := request.URL.Query().Get("days"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed != 7 && parsed != 30 && parsed != 90 {
			writeError(writer, http.StatusBadRequest, "invalid_request", "days must be 7, 30 or 90")
			return
		}
		days = parsed
	}
	now := s.config.Now().UTC()
	end := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	start := end.AddDate(0, 0, -days)
	session := sessionFromContext(request.Context())
	tenantID := ""
	if session.Account.Role == iam.RoleTenant {
		tenantID = session.Account.TenantID
	}
	summary, err := s.repository.ReadUsageSummary(request.Context(), tenantID, start, end)
	if err != nil {
		s.internalError(writer, "read usage summary", err)
		return
	}
	byDay := make(map[string]uint64, len(summary.Series))
	for _, point := range summary.Series {
		byDay[point.Day] = point.Bytes
	}
	series := make([]usageSeriesPoint, 0, days)
	for day := start; day.Before(end); day = day.AddDate(0, 0, 1) {
		series = append(series, usageSeriesPoint{Timestamp: day, Bytes: byDay[day.Format("2006-01-02")]})
	}
	names := make(map[string]string)
	if record, err := s.repository.ActiveClusterPlan(request.Context(), s.config.PlanID); err == nil {
		for _, forward := range record.Plan.Forwards {
			names[forward.ID] = fmt.Sprintf("%s:%d", forward.Listen.Address, forward.Listen.Port)
		}
	}
	byForward := make([]usageForwardView, 0, len(summary.ByForward))
	for _, item := range summary.ByForward {
		name := names[item.ForwardID]
		if name == "" {
			name = item.ForwardID
		}
		byForward = append(byForward, usageForwardView{
			ForwardID: item.ForwardID, Name: name, Protocol: item.Protocol, Bytes: item.Bytes,
		})
	}
	var quotaBytes any
	var rateLimitMbps any
	var expiresAt any
	if tenantID != "" {
		policy, err := s.repository.TenantPolicy(request.Context(), tenantID)
		if err != nil {
			s.writeRepositoryError(writer, err)
			return
		}
		tenant, err := s.repository.TenantByID(request.Context(), tenantID)
		if err != nil {
			s.writeRepositoryError(writer, err)
			return
		}
		if policy.TrafficQuotaBytes > 0 {
			quotaBytes = policy.TrafficQuotaBytes
		}
		rate := policy.IngressRateLimitBPS
		if policy.EgressRateLimitBPS > rate {
			rate = policy.EgressRateLimitBPS
		}
		if rate > 0 {
			rateLimitMbps = float64(rate) / 1_000_000
		}
		if tenant.ExpiresAt != nil {
			expiresAt = tenant.ExpiresAt
		}
	}
	writeData(writer, http.StatusOK, map[string]any{
		"measurement":     "L3 bytes including IP headers and retransmissions",
		"range_days":      days,
		"series":          series,
		"by_forward":      byForward,
		"quota":           map[string]any{"used_bytes": summary.TotalBytes, "quota_bytes": quotaBytes},
		"rate_limit_mbps": rateLimitMbps,
		"expires_at":      expiresAt,
	})
}
