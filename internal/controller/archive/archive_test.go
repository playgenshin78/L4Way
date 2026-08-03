package archive

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
)

func TestCreateAndRestoreSingleArchive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sourceDirectory := t.TempDir()
	databasePath := filepath.Join(sourceDirectory, "flux.db")
	keyPath := filepath.Join(sourceDirectory, "controller-noise.key")
	repository, err := store.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.CreateEnrollmentToken(ctx, "node-a", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	identity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := securechannel.WriteKeyPair(keyPath, identity); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "flux-backup.tar.gz")
	if err := Create(ctx, repository, keyPath, archivePath); err != nil {
		t.Fatal(err)
	}
	repository.Close()

	restoreDirectory := t.TempDir()
	restoredDatabase := filepath.Join(restoreDirectory, "flux.db")
	restoredKey := filepath.Join(restoreDirectory, "controller-noise.key")
	if err := Restore(ctx, archivePath, restoredDatabase, restoredKey); err != nil {
		t.Fatal(err)
	}
	restoredIdentity, err := securechannel.LoadKeyPair(restoredKey)
	if err != nil {
		t.Fatal(err)
	}
	if securechannel.Fingerprint(restoredIdentity.Public) != securechannel.Fingerprint(identity.Public) {
		t.Fatal("restored Controller identity changed")
	}
	restoredStore, err := store.Open(ctx, restoredDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredStore.Close()
	if err := restoredStore.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restoredStore.CreateEnrollmentToken(ctx, "node-b", 10*time.Minute); err != nil {
		t.Fatalf("restored SQLite database is not writable: %v", err)
	}
}
