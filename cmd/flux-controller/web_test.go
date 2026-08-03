package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithWebUIRoutesAPIAssetsAndSPA(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>flux</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app.js"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
	})
	handler, err := withWebUI(api, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path   string
		status int
		body   string
		cache  string
	}{
		{path: "/api/v1/auth/me", status: http.StatusTeapot},
		{path: "/assets/app.js", status: http.StatusOK, body: "ok", cache: "immutable"},
		{path: "/forwards", status: http.StatusOK, body: "flux", cache: "no-cache"},
		{path: "/assets/missing.js", status: http.StatusNotFound},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != test.status {
			t.Fatalf("%s status=%d want=%d", test.path, recorder.Code, test.status)
		}
		if test.body != "" && !strings.Contains(recorder.Body.String(), test.body) {
			t.Fatalf("%s body=%q", test.path, recorder.Body.String())
		}
		if test.cache != "" && !strings.Contains(recorder.Header().Get("Cache-Control"), test.cache) {
			t.Fatalf("%s cache=%q", test.path, recorder.Header().Get("Cache-Control"))
		}
	}
}

func TestWithWebUIRequiresIndex(t *testing.T) {
	if _, err := withWebUI(http.NotFoundHandler(), t.TempDir()); err == nil {
		t.Fatal("expected missing index to fail")
	}
}
