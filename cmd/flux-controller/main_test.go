package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/controller/store"
)

func TestOwnerInitIfMissingPreservesExistingPassword(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "flux.db")
	firstPasswordPath := filepath.Join(directory, "owner-password")
	secondPasswordPath := filepath.Join(directory, "replacement-password")
	if err := os.WriteFile(firstPasswordPath, []byte("first-owner-password-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPasswordPath, []byte("replacement-password-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{
		"owner-init", "--database", databasePath, "--username", "owner",
		"--display-name", "Owner", "--password-file", firstPasswordPath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("first owner-init code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"owner-init", "--database", databasePath, "--username", "owner",
		"--display-name", "Owner", "--password-file", secondPasswordPath, "--if-missing",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("idempotent owner-init code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"created": false`) {
		t.Fatalf("idempotent owner-init output=%s", stdout.String())
	}

	repository, err := store.Open(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	account, err := repository.AccountByUsername(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if !iam.VerifyPassword(account.PasswordHash, "first-owner-password-value") {
		t.Fatal("original Owner password no longer works")
	}
	if iam.VerifyPassword(account.PasswordHash, "replacement-password-value") {
		t.Fatal("--if-missing replaced the existing Owner password")
	}
}
