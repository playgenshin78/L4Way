package archive

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
)

const (
	databaseEntry = "flux.db"
	keyEntry      = "controller-noise.key"
	manifestEntry = "manifest.json"
)

type Manifest struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	Files     map[string]string `json:"sha256"`
}

func Create(ctx context.Context, repository *store.Store, controllerKeyPath, outputPath string) error {
	if repository == nil {
		return errors.New("Controller store is required")
	}
	if _, err := securechannel.LoadKeyPair(controllerKeyPath); err != nil {
		return err
	}
	outputPath, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return fmt.Errorf("resolve backup archive path: %w", err)
	}
	if _, err := os.Stat(outputPath); err == nil {
		return fmt.Errorf("backup archive already exists: %s", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup archive: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	temporaryDirectory, err := os.MkdirTemp(filepath.Dir(outputPath), ".flux-backup-*")
	if err != nil {
		return fmt.Errorf("create backup workspace: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	databaseSnapshot := filepath.Join(temporaryDirectory, databaseEntry)
	if err := repository.BackupTo(ctx, databaseSnapshot); err != nil {
		return err
	}
	databaseHash, err := fileHash(databaseSnapshot)
	if err != nil {
		return err
	}
	keyHash, err := fileHash(controllerKeyPath)
	if err != nil {
		return err
	}
	manifest := Manifest{Version: 1, CreatedAt: time.Now().UTC(), Files: map[string]string{databaseEntry: databaseHash, keyEntry: keyHash}}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode backup manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')
	temporaryArchive := filepath.Join(temporaryDirectory, "archive.tmp")
	if err := writeArchive(temporaryArchive, manifestJSON, databaseSnapshot, controllerKeyPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryArchive, outputPath); err != nil {
		return fmt.Errorf("install backup archive: %w", err)
	}
	return os.Chmod(outputPath, 0o600)
}

func Restore(ctx context.Context, archivePath, databasePath, controllerKeyPath string) error {
	for _, target := range []string{databasePath, controllerKeyPath} {
		if _, err := os.Stat(filepath.Clean(target)); err == nil {
			return fmt.Errorf("restore target already exists: %s", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect restore target %s: %w", target, err)
		}
	}
	temporaryDirectory, err := os.MkdirTemp("", "flux-restore-*")
	if err != nil {
		return fmt.Errorf("create restore workspace: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	manifest, err := extractArchive(archivePath, temporaryDirectory)
	if err != nil {
		return err
	}
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported Flux backup version %d", manifest.Version)
	}
	for _, name := range []string{databaseEntry, keyEntry} {
		expected := manifest.Files[name]
		actual, err := fileHash(filepath.Join(temporaryDirectory, name))
		if err != nil {
			return err
		}
		if expected == "" || actual != expected {
			return fmt.Errorf("backup checksum mismatch for %s", name)
		}
	}
	if _, err := securechannel.LoadKeyPair(filepath.Join(temporaryDirectory, keyEntry)); err != nil {
		return fmt.Errorf("validate restored Controller identity: %w", err)
	}
	validationStore, err := store.Open(ctx, filepath.Join(temporaryDirectory, databaseEntry))
	if err != nil {
		return fmt.Errorf("validate restored SQLite database: %w", err)
	}
	if err := validationStore.Migrate(ctx); err != nil {
		validationStore.Close()
		return fmt.Errorf("validate restored SQLite schema: %w", err)
	}
	validationStore.Close()

	installedDatabase := false
	if err := installFile(filepath.Join(temporaryDirectory, databaseEntry), databasePath); err != nil {
		return err
	}
	installedDatabase = true
	if err := installFile(filepath.Join(temporaryDirectory, keyEntry), controllerKeyPath); err != nil {
		if installedDatabase {
			_ = os.Remove(databasePath)
		}
		return err
	}
	return nil
}

func writeArchive(path string, manifest []byte, databasePath, keyPath string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create backup archive: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeBytesEntry(tarWriter, manifestEntry, manifest, 0o600); err != nil {
		return err
	}
	if err := writeFileEntry(tarWriter, databaseEntry, databasePath); err != nil {
		return err
	}
	if err := writeFileEntry(tarWriter, keyEntry, keyPath); err != nil {
		return err
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("finish backup tar stream: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("finish backup compression: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync backup archive: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close backup archive: %w", err)
	}
	remove = false
	return nil
}

func writeBytesEntry(writer *tar.Writer, name string, data []byte, mode int64) error {
	header := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Now().UTC()}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup header %s: %w", name, err)
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write backup entry %s: %w", name, err)
	}
	return nil
}

func writeFileEntry(writer *tar.Writer, name, path string) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("open backup source %s: %w", name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat backup source %s: %w", name, err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
		return fmt.Errorf("write backup header %s: %w", name, err)
	}
	if _, err := io.Copy(writer, file); err != nil {
		return fmt.Errorf("write backup entry %s: %w", name, err)
	}
	return nil
}

func extractArchive(path, destination string) (Manifest, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup archive: %w", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup compression: %w", err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	seen := make(map[string]bool)
	var manifest Manifest
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read backup archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || (header.Name != manifestEntry && header.Name != databaseEntry && header.Name != keyEntry) || seen[header.Name] {
			return Manifest{}, fmt.Errorf("backup contains invalid entry %q", header.Name)
		}
		seen[header.Name] = true
		if header.Size < 0 || header.Name != databaseEntry && header.Size > 1<<20 {
			return Manifest{}, fmt.Errorf("backup entry %s has an invalid size", header.Name)
		}
		entryPath := filepath.Join(destination, header.Name)
		entry, err := os.OpenFile(entryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return Manifest{}, fmt.Errorf("create restored entry %s: %w", header.Name, err)
		}
		_, copyErr := io.CopyN(entry, reader, header.Size)
		closeErr := entry.Close()
		if copyErr != nil {
			return Manifest{}, fmt.Errorf("extract backup entry %s: %w", header.Name, copyErr)
		}
		if closeErr != nil {
			return Manifest{}, fmt.Errorf("close restored entry %s: %w", header.Name, closeErr)
		}
	}
	if !seen[manifestEntry] || !seen[databaseEntry] || !seen[keyEntry] {
		return Manifest{}, errors.New("backup archive is incomplete")
	}
	encoded, err := os.ReadFile(filepath.Join(destination, manifestEntry))
	if err != nil {
		return Manifest{}, err
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
	}
	return manifest, nil
}

func installFile(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("create restore target directory: %w", err)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(target), ".flux-restore-*.tmp")
	if err != nil {
		return fmt.Errorf("create restore target: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, input); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("copy restored file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return fmt.Errorf("install restored file %s: %w", target, err)
	}
	return nil
}

func fileHash(path string) (string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("open %s for checksum: %w", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("checksum %s: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
