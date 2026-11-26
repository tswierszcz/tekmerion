package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var hashPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type Artifact struct {
	SHA       string `json:"sha256"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

// Put publishes complete evidence without overwriting an existing artifact.
// A crash before SQL registration can leave an unreferenced file, never a
// committed reference to a partially written file.
func (s *Store) Put(ctx context.Context, raw []byte, mediaType string) (*Artifact, error) {
	if mediaType == "" {
		return nil, fmt.Errorf("artifact media type required")
	}
	a := &Artifact{SHA: digest(raw), Size: int64(len(raw)), MediaType: mediaType}
	dir := filepath.Join(s.dir, "artifacts")
	destination := filepath.Join(dir, a.SHA[7:])
	temp, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err := temp.Write(raw); err != nil {
		return nil, err
	}
	if err := temp.Chmod(0400); err != nil {
		return nil, err
	}
	if err := temp.Sync(); err != nil {
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(temp.Name(), destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		existing, err := readArtifact(destination, a)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(existing, raw) {
			return nil, fmt.Errorf("artifact collision")
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return nil, syncErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if _, err := s.db.ExecContext(ctx, "INSERT INTO artifacts VALUES(?,?,?) ON CONFLICT(sha) DO NOTHING", a.SHA, a.Size, a.MediaType); err != nil {
		return nil, err
	}
	// A hash can have several uses; its first recorded media type is canonical.
	if err := s.db.QueryRowContext(ctx, "SELECT size,media_type FROM artifacts WHERE sha=?", a.SHA).Scan(&a.Size, &a.MediaType); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) Get(ctx context.Context, sha string) ([]byte, error) {
	if !hashPattern.MatchString(sha) {
		return nil, fmt.Errorf("invalid artifact hash")
	}
	a := &Artifact{SHA: sha}
	if err := s.db.QueryRowContext(ctx, "SELECT size,media_type FROM artifacts WHERE sha=?", sha).Scan(&a.Size, &a.MediaType); err != nil {
		return nil, err
	}
	return readArtifact(filepath.Join(s.dir, "artifacts", sha[7:]), a)
}
func readArtifact(path string, a *Artifact) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != a.Size {
		return nil, fmt.Errorf("artifact %s is not a regular file of recorded size", a.SHA)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, a.Size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != a.Size || digest(raw) != a.SHA {
		return nil, fmt.Errorf("artifact %s hash mismatch", a.SHA)
	}
	return raw, nil
}
