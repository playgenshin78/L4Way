package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	_ "modernc.org/sqlite"
)

type database struct {
	*sql.DB
}

type transaction struct {
	*sql.Tx
}

type commandResult struct {
	result sql.Result
}

type rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}

type row interface {
	Scan(...any) error
}

type queryer interface {
	Exec(context.Context, string, ...any) (commandResult, error)
	Query(context.Context, string, ...any) (rows, error)
	QueryRow(context.Context, string, ...any) row
}

var forUpdatePattern = regexp.MustCompile(`(?i)\s+FOR\s+UPDATE(?:\s+OF\s+[A-Za-z0-9_.,]+)?(?:\s+SKIP\s+LOCKED)?`)

func openSQLite(ctx context.Context, path string) (*database, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, "", errors.New("SQLite database path must not be empty")
	}
	var dsn string
	resolvedPath := path
	if path == ":memory:" {
		dsn = "file:flux-memory?mode=memory&cache=shared"
		resolvedPath = path
	} else {
		absolute, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			return nil, "", fmt.Errorf("resolve SQLite database path: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			return nil, "", fmt.Errorf("create SQLite database directory: %w", err)
		}
		resolvedPath = absolute
		uriPath := filepath.ToSlash(absolute)
		if filepath.VolumeName(absolute) != "" {
			uriPath = "/" + uriPath
		}
		dsn = (&url.URL{Scheme: "file", Path: uriPath}).String()
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	dsn += separator + "_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(FULL)&_time_format=sqlite"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, "", fmt.Errorf("open SQLite database: %w", err)
	}
	// A single Controller owns the database and serializes all writes through
	// one connection. This also makes SQLite's deferred transactions safe from
	// in-process writer upgrade races.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, "", fmt.Errorf("ping SQLite database: %w", err)
	}
	if resolvedPath != ":memory:" {
		if err := os.Chmod(resolvedPath, 0o600); err != nil {
			db.Close()
			return nil, "", fmt.Errorf("protect SQLite database: %w", err)
		}
	}
	return &database{DB: db}, resolvedPath, nil
}

func (d *database) Begin(ctx context.Context) (*transaction, error) {
	tx, err := d.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	return &transaction{Tx: tx}, nil
}

func (d *database) Exec(ctx context.Context, query string, args ...any) (commandResult, error) {
	result, err := d.ExecContext(ctx, rewriteQuery(query), args...)
	return commandResult{result: result}, err
}

func (d *database) Query(ctx context.Context, query string, args ...any) (rows, error) {
	return d.QueryContext(ctx, rewriteQuery(query), args...)
}

func (d *database) QueryRow(ctx context.Context, query string, args ...any) row {
	return d.QueryRowContext(ctx, rewriteQuery(query), args...)
}

func (t *transaction) Exec(ctx context.Context, query string, args ...any) (commandResult, error) {
	result, err := t.ExecContext(ctx, rewriteQuery(query), args...)
	return commandResult{result: result}, err
}

func (t *transaction) Query(ctx context.Context, query string, args ...any) (rows, error) {
	return t.QueryContext(ctx, rewriteQuery(query), args...)
}

func (t *transaction) QueryRow(ctx context.Context, query string, args ...any) row {
	return t.QueryRowContext(ctx, rewriteQuery(query), args...)
}

func (t *transaction) Commit(context.Context) error   { return t.Tx.Commit() }
func (t *transaction) Rollback(context.Context) error { return t.Tx.Rollback() }

func (r commandResult) RowsAffected() int64 {
	if r.result == nil {
		return 0
	}
	count, _ := r.result.RowsAffected()
	return count
}

func (r commandResult) LastInsertID() int64 {
	if r.result == nil {
		return 0
	}
	id, _ := r.result.LastInsertId()
	return id
}

func rewriteQuery(query string) string {
	query = replaceNumberedParameters(query)
	query = strings.ReplaceAll(query, "now()", "CURRENT_TIMESTAMP")
	query = strings.ReplaceAll(query, "NOW()", "CURRENT_TIMESTAMP")
	query = forUpdatePattern.ReplaceAllString(query, "")
	return query
}

func replaceNumberedParameters(query string) string {
	var result strings.Builder
	result.Grow(len(query))
	for index := 0; index < len(query); index++ {
		if query[index] != '$' || index+1 >= len(query) || query[index+1] < '0' || query[index+1] > '9' {
			result.WriteByte(query[index])
			continue
		}
		result.WriteByte('?')
		index++
		for ; index < len(query) && query[index] >= '0' && query[index] <= '9'; index++ {
			result.WriteByte(query[index])
		}
		index--
	}
	return result.String()
}
