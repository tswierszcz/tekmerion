// Package ariadne is Tekmerion's adapter for the Ariadne research interface
// (contract 1.0.0-draft.1, vendored under contracts/ariadne/v1 and pinned by
// contracts/ariadne/PIN.json). It runs the real `ariadne research index` and
// `ariadne research query` commands, or replays the recorded contract
// fixtures, and checks every response against the request it answers.
package ariadne

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Contract constants of the pinned revision.
const (
	ContractRevision = "1.0.0-draft.1"
	QuerySchema      = "ariadne-research-query-1"
	ResponseSchema   = "ariadne-research-response-1"
	BundleSchema     = "ariadne-research-bundle-1"
	// MaxTargets is the largest reachability batch a request may carry.
	MaxTargets = 256
)

// Pin is contracts/ariadne/PIN.json.
type Pin struct {
	ContractRevision     string            `json:"contract_revision"`
	Status               string            `json:"status"`
	UpstreamRepository   string            `json:"upstream_repository"`
	UpstreamPath         string            `json:"upstream_path"`
	UpstreamCommit       *string           `json:"upstream_commit"`
	UpstreamCodeBaseline string            `json:"upstream_code_baseline"`
	Files                map[string]string `json:"files"`
}

// LoadPin reads a PIN.json file.
func LoadPin(path string) (*Pin, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Pin
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Verify checks that dir holds exactly the pinned files with the pinned
// hashes, and that the pin names the revision this adapter implements.
func (p *Pin) Verify(dir string) error {
	if p.ContractRevision != ContractRevision {
		return fmt.Errorf("pin names contract %s, adapter implements %s", p.ContractRevision, ContractRevision)
	}
	var present []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		present = append(present, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(present)
	for _, rel := range present {
		want, ok := p.Files[rel]
		if !ok {
			return fmt.Errorf("%s is not pinned", rel)
		}
		got, err := fileSHA256(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s: hash %s, pinned %s", rel, got, want)
		}
	}
	if len(present) != len(p.Files) {
		return fmt.Errorf("%d pinned files, %d present", len(p.Files), len(present))
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Of(raw), nil
}

func sha256Of(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
