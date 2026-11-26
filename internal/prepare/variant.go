package prepare

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/tswierszcz/tekmerion/internal/manifest"
)

const VariantSchema = "tekmerion-variant-1"

// ChangedFile is one source file the correction added, removed or changed.
// Empty Before/After means absent; link targets are recorded as "link T".
type ChangedFile struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Variant is a corrected copy of a prepared target: the same revision with an
// operator-supplied patch, built by the same recipe in a separate directory.
// The original preparation is never modified.
type Variant struct {
	Schema         string             `json:"schema_version"`
	PatchSHA256    string             `json:"patch_sha256"`
	BaseTreeSHA256 string             `json:"base_tree_sha256"`
	TreeSHA256     string             `json:"tree_sha256"`
	Files          int                `json:"files"`
	Changed        []ChangedFile      `json:"changed"`
	Build          manifest.Build     `json:"build"`
	Artifacts      manifest.Artifacts `json:"artifacts"`
}

func treeFiles(dir string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			files[rel] = "link " + t
		case d.Type().IsRegular():
			h, err := fileSHA(p)
			if err != nil {
				return err
			}
			files[rel] = h
		default:
			return fmt.Errorf("%s is not a regular file", rel)
		}
		return nil
	})
	return files, err
}

// copyTree copies regular files, directories and symlinks with their
// permission bits; anything else is refused.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if rel == "." {
				return nil
			}
			return os.Mkdir(to, info.Mode().Perm()|0o700)
		case d.Type()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(t, to)
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(to, b, info.Mode().Perm()|0o600)
		}
		return fmt.Errorf("%s is not a regular file", rel)
	})
}

// BuildVariant copies the verified source tree into dir (which must not
// exist), applies patch with git apply (which refuses paths outside the tree
// and through symlinks), and builds the copy with the project's recipe and
// network policy. The original tree is re-hashed afterwards.
func BuildVariant(ctx context.Context, v *Verified, patch []byte, dir string, log io.Writer) (*Variant, error) {
	if v == nil || v.Run == nil || v.Project == nil {
		return nil, errors.New("variant: needs a verified preparation")
	}
	if len(patch) == 0 {
		return nil, errors.New("variant: empty patch")
	}
	if log == nil {
		log = io.Discard
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("variant: directory: %w", err)
	}
	for _, d := range []string{"src", "out", "home", "tmp", "logs"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	origSrc, src := filepath.Join(v.Work, "src"), filepath.Join(dir, "src")
	r := &Variant{Schema: VariantSchema, PatchSHA256: sha256Hex(patch), BaseTreeSHA256: v.Run.Source.TreeSHA256, Changed: []ChangedFile{}}
	if base, _, err := treeHash(origSrc); err != nil || base != r.BaseTreeSHA256 {
		return nil, fmt.Errorf("variant: prepared source differs from its manifest (%v)", err)
	}
	if err := copyTree(origSrc, src); err != nil {
		return nil, err
	}
	patchFile := filepath.Join(dir, "correction.patch")
	if err := os.WriteFile(patchFile, patch, 0o600); err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "apply", "-p1", "--whitespace=nowarn", "--", patchFile)
	cmd.Dir, cmd.Stderr = src, &stderr
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(dir, "home"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CEILING_DIRECTORIES=" + dir}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("variant: patch does not apply: %v: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	before, err := treeFiles(origSrc)
	if err != nil {
		return nil, err
	}
	after, err := treeFiles(src)
	if err != nil {
		return nil, err
	}
	for p, h := range after {
		if before[p] != h {
			r.Changed = append(r.Changed, ChangedFile{Path: p, Before: before[p], After: h})
		}
	}
	for p, h := range before {
		if _, ok := after[p]; !ok {
			r.Changed = append(r.Changed, ChangedFile{Path: p, Before: h})
		}
	}
	sort.Slice(r.Changed, func(i, j int) bool { return r.Changed[i].Path < r.Changed[j].Path })
	if len(r.Changed) == 0 {
		return nil, errors.New("variant: patch changed no source file")
	}
	if r.TreeSHA256, r.Files, err = treeHash(src); err != nil {
		return nil, err
	}
	if r.Build, err = build(ctx, v.Project, v.Run.Source.CommitTime, dir, log); err != nil {
		return r, err
	}
	if tree, _, err := treeHash(src); err != nil || tree != r.TreeSHA256 {
		return r, errors.New("variant: the build changed the corrected source tree")
	}
	if r.Artifacts, err = artifacts(filepath.Join(dir, "out"), v.Project.Build.Outputs); err != nil {
		return r, err
	}
	if base, _, err := treeHash(origSrc); err != nil || base != r.BaseTreeSHA256 {
		return r, errors.New("variant: the original prepared source changed")
	}
	return r, nil
}

// CheckVariant recomputes the corrected tree and build outputs.
func CheckVariant(dir string, r *Variant, outputs manifest.Outputs) error {
	tree, _, err := treeHash(filepath.Join(dir, "src"))
	if err != nil || tree != r.TreeSHA256 {
		return fmt.Errorf("variant source changed (%v)", err)
	}
	a, err := artifacts(filepath.Join(dir, "out"), outputs)
	if err != nil || a.ClasspathSHA256 != r.Artifacts.ClasspathSHA256 || a.App.SHA256 != r.Artifacts.App.SHA256 {
		return fmt.Errorf("variant build outputs changed (%v)", err)
	}
	return nil
}
