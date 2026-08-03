package management

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleSystemStatus(writer http.ResponseWriter, request *http.Request) {
	now := s.config.Now().UTC()
	nodes, nodeErr := s.repository.ListNodes(request.Context(), 500, 0)
	online := 0
	for _, node := range nodes {
		if node.RevokedAt == nil && node.LastSeenAt != nil && now.Sub(node.LastSeenAt.UTC()) <= s.config.NodeOfflineAfter {
			online++
		}
	}
	databaseSize := int64(0)
	databaseHealthy := nodeErr == nil
	if strings.TrimSpace(s.config.DatabasePath) != "" && s.config.DatabasePath != ":memory:" {
		info, err := os.Stat(s.config.DatabasePath)
		if err != nil {
			databaseHealthy = false
		} else {
			databaseSize = info.Size()
		}
	}
	var lastBackup any
	if _, createdAt, _, err := latestBackup(s.config.BackupDirectory); err == nil && !createdAt.IsZero() {
		lastBackup = createdAt
	}
	writeData(writer, http.StatusOK, map[string]any{
		"controller_version": s.config.ControllerVersion,
		"agent_min_version":  s.config.AgentMinVersion,
		"encryption":         "Noise IK / X25519 / AES-256-GCM / SHA-256",
		"uptime_seconds":     uint64(now.Sub(s.config.StartedAt.UTC()).Seconds()),
		"sqlite": map[string]any{
			"path": s.config.DatabasePath, "size_bytes": databaseSize,
			"wal_enabled": true, "healthy": databaseHealthy,
		},
		"last_backup_at": lastBackup,
		"nodes_online":   online,
		"nodes_total":    len(nodes),
	})
}

func (s *Server) handleSystemBackup(writer http.ResponseWriter, request *http.Request) {
	if s.config.Backup == nil || strings.TrimSpace(s.config.BackupDirectory) == "" {
		writeError(writer, http.StatusConflict, "backup_not_configured", "Controller backup directory is not configured")
		return
	}
	backupID, _, createdAt, size, err := s.createSystemBackup(request.Context())
	if err != nil {
		s.internalError(writer, "create Controller backup", err)
		return
	}
	session := sessionFromContext(request.Context())
	s.auditSession(request.Context(), request, session, "system.backup.create", "backup", backupID, "success", map[string]any{"size_bytes": size})
	writeData(writer, http.StatusCreated, map[string]any{
		"backup_id": backupID, "created_at": createdAt, "size_bytes": size,
	})
}

func (s *Server) handleSystemBackupDownload(writer http.ResponseWriter, request *http.Request) {
	if strings.TrimSpace(s.config.BackupDirectory) == "" {
		writeError(writer, http.StatusConflict, "backup_not_configured", "Controller backup directory is not configured")
		return
	}
	filename, _, size, err := latestBackup(s.config.BackupDirectory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(writer, http.StatusNotFound, "backup_not_found", "No Controller backup is available")
			return
		}
		s.internalError(writer, "find latest Controller backup", err)
		return
	}
	backupID := strings.TrimSuffix(filename, ".tar.gz")
	path := filepath.Join(s.config.BackupDirectory, filename)
	file, err := os.Open(path)
	if err != nil {
		s.internalError(writer, "open latest Controller backup", err)
		return
	}
	defer file.Close()

	session := sessionFromContext(request.Context())
	s.auditSession(request.Context(), request, session, "system.backup.download", "backup", backupID, "success", map[string]any{"size_bytes": size})
	writer.Header().Set("Content-Type", "application/gzip")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	writer.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	if _, err := io.Copy(writer, file); err != nil {
		s.logger.Error("stream Controller backup", "backup_id", backupID, "error", err)
	}
}

func (s *Server) createSystemBackup(ctx context.Context) (string, string, time.Time, int64, error) {
	now := s.config.Now().UTC()
	backupID := "flux-backup-" + now.Format("20060102T150405.000000000Z")
	path := filepath.Join(s.config.BackupDirectory, backupID+".tar.gz")
	if err := s.config.Backup(ctx, path); err != nil {
		return "", "", time.Time{}, 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "", time.Time{}, 0, err
	}
	return backupID, path, now, info.Size(), nil
}

func latestBackup(directory string) (string, time.Time, int64, error) {
	if strings.TrimSpace(directory) == "" {
		return "", time.Time{}, 0, errors.New("backup directory is not configured")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", time.Time{}, 0, err
	}
	type candidate struct {
		name string
		time time.Time
		size int64
	}
	var candidates []candidate
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "flux-backup-") || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{name: entry.Name(), time: info.ModTime().UTC(), size: info.Size()})
	}
	if len(candidates) == 0 {
		return "", time.Time{}, 0, os.ErrNotExist
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].time.After(candidates[j].time) })
	return candidates[0].name, candidates[0].time, candidates[0].size, nil
}
