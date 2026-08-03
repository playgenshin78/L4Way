package store

import (
	"context"
	"fmt"
	"time"
)

type UsageSeriesPoint struct {
	Day   string `json:"day"`
	Bytes uint64 `json:"bytes"`
}

type UsageForwardTotal struct {
	ForwardID string `json:"forward_id"`
	Protocol  string `json:"protocol"`
	Bytes     uint64 `json:"bytes"`
}

type UsageSummary struct {
	Series     []UsageSeriesPoint
	ByForward  []UsageForwardTotal
	TotalBytes uint64
}

func (s *Store) ReadUsageSummary(ctx context.Context, tenantID string, since, until time.Time) (UsageSummary, error) {
	if !since.Before(until) {
		return UsageSummary{}, fmt.Errorf("usage time range must be positive")
	}
	filter := ""
	arguments := []any{since.UTC(), until.UTC()}
	if tenantID != "" {
		filter = " AND d.user_id=$3"
		arguments = append(arguments, tenantID)
	}
	rows, err := s.pool.Query(ctx, `
SELECT strftime('%Y-%m-%d',b.observed_at),COALESCE(SUM(d.bytes),0)
FROM usage_deltas d
JOIN usage_batches b ON b.node_id=d.node_id AND b.counter_epoch=d.counter_epoch AND b.sequence=d.sequence
WHERE b.observed_at >= $1 AND b.observed_at < $2`+filter+`
GROUP BY strftime('%Y-%m-%d',b.observed_at)
ORDER BY strftime('%Y-%m-%d',b.observed_at)`, arguments...)
	if err != nil {
		return UsageSummary{}, fmt.Errorf("read usage series: %w", err)
	}
	result := UsageSummary{Series: []UsageSeriesPoint{}, ByForward: []UsageForwardTotal{}}
	for rows.Next() {
		var point UsageSeriesPoint
		var bytes int64
		if err := rows.Scan(&point.Day, &bytes); err != nil {
			rows.Close()
			return UsageSummary{}, fmt.Errorf("scan usage series: %w", err)
		}
		if bytes >= 0 {
			point.Bytes = uint64(bytes)
		}
		result.Series = append(result.Series, point)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return UsageSummary{}, fmt.Errorf("iterate usage series: %w", err)
	}
	rows.Close()

	rows, err = s.pool.Query(ctx, `
SELECT d.forward_id,d.protocol,COALESCE(SUM(d.bytes),0)
FROM usage_deltas d
JOIN usage_batches b ON b.node_id=d.node_id AND b.counter_epoch=d.counter_epoch AND b.sequence=d.sequence
WHERE b.observed_at >= $1 AND b.observed_at < $2`+filter+`
GROUP BY d.forward_id,d.protocol
ORDER BY COALESCE(SUM(d.bytes),0) DESC,d.forward_id,d.protocol`, arguments...)
	if err != nil {
		return UsageSummary{}, fmt.Errorf("read usage by forward: %w", err)
	}
	for rows.Next() {
		var item UsageForwardTotal
		var bytes int64
		if err := rows.Scan(&item.ForwardID, &item.Protocol, &bytes); err != nil {
			rows.Close()
			return UsageSummary{}, fmt.Errorf("scan usage by forward: %w", err)
		}
		if bytes >= 0 {
			item.Bytes = uint64(bytes)
		}
		result.ByForward = append(result.ByForward, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return UsageSummary{}, fmt.Errorf("iterate usage by forward: %w", err)
	}
	rows.Close()

	totalQuery := `SELECT COALESCE(SUM(bytes),0) FROM usage_rollups`
	totalArguments := []any{}
	if tenantID != "" {
		totalQuery += ` WHERE user_id=$1`
		totalArguments = append(totalArguments, tenantID)
	}
	var total int64
	if err := s.pool.QueryRow(ctx, totalQuery, totalArguments...).Scan(&total); err != nil {
		return UsageSummary{}, fmt.Errorf("read lifetime usage: %w", err)
	}
	if total >= 0 {
		result.TotalBytes = uint64(total)
	}
	return result, nil
}
