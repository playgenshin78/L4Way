package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func withWebUI(api http.Handler, root string) (http.Handler, error) {
	if api == nil {
		return nil, errors.New("management API handler is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve web root: %w", err)
	}
	indexPath := filepath.Join(absolute, "index.html")
	info, err := os.Stat(indexPath)
	if err != nil || info.IsDir() {
		return nil, fmt.Errorf("web root must contain index.html: %s", absolute)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api" || strings.HasPrefix(request.URL.Path, "/api/") {
			api.ServeHTTP(writer, request)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.NotFound(writer, request)
			return
		}
		setWebSecurityHeaders(writer)
		relative := strings.TrimPrefix(filepath.Clean("/"+request.URL.Path), string(filepath.Separator))
		candidate := filepath.Join(absolute, relative)
		if withinRoot(absolute, candidate) {
			if candidateInfo, statErr := os.Stat(candidate); statErr == nil && !candidateInfo.IsDir() {
				if strings.HasPrefix(filepath.ToSlash(relative), "assets/") {
					writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					writer.Header().Set("Cache-Control", "no-cache")
				}
				http.ServeFile(writer, request, candidate)
				return
			}
		}
		if strings.HasPrefix(request.URL.Path, "/assets/") {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(writer, request, indexPath)
	}), nil
}

func withinRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func setWebSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}
