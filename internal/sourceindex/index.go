// Package sourceindex maps Ariadne method identities (class, JVM method name,
// descriptor) to source files and line ranges in a prepared source tree.
//
// Tekmerion builds its own index from the prepared artifacts: every class
// file's SourceFile attribute names the file within the class's package
// directory, and each method's LineNumberTable gives its first and last line.
// Methods are keyed by the SHA-256 of their class file, the same class_sha256
// Ariadne reports, so a method resolves to the exact copy that was analysed
// even when several jars carry a class of the same name.
//
// Ariadne's own Source record is preferred when it carries a path or lines;
// Resolve cross-checks it against this index and reports any disagreement
// instead of choosing one side.
package sourceindex

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Schema is the schema_version of a saved index.
const Schema = "tekmerion-source-index-1"

// Source bindings, the contract's vocabulary.
const (
	BindingBuildVerified = "build_verified" // the artifact was built from this file by the recorded build
	BindingDeclared      = "declared"       // the class names the file, which is not in the prepared tree
	BindingUnavailable   = "unavailable"
)

// Root ties a source root (relative to the prepared checkout) to the artifact
// built from it (relative to the build output directory).
type Root struct {
	Path     string `json:"path"`
	Artifact string `json:"artifact"`
}

// Entry is one method of one class file.
type Entry struct {
	Artifact     string  `json:"artifact"`
	Class        string  `json:"class"`
	ClassSHA256  string  `json:"class_sha256"`
	Name         string  `json:"name"`
	Descriptor   string  `json:"descriptor"`
	Path         *string `json:"path"` // relative to the prepared checkout
	LineStart    *int    `json:"line_start"`
	LineEnd      *int    `json:"line_end"`
	SourceSHA256 *string `json:"source_sha256"`
	Binding      string  `json:"binding"`
}

// Index is a saved source index.
type Index struct {
	SchemaVersion string  `json:"schema_version"`
	Roots         []Root  `json:"roots"`
	Entries       []Entry `json:"entries"`

	byHash map[string]int
	byName map[string][]int
}

func methodKey(a, b, c string) string { return a + "\x00" + b + "\x00" + c }

// Build indexes every class in each root's artifact against the source
// files under checkout/root.Path.
func Build(checkout, outDir string, roots []Root) (*Index, error) {
	ix := &Index{SchemaVersion: Schema, Roots: roots}
	fileHash := map[string]string{}
	for _, r := range roots {
		if err := cleanRel(r.Path); err != nil {
			return nil, fmt.Errorf("source root %q: %w", r.Path, err)
		}
		if err := cleanRel(r.Artifact); err != nil {
			return nil, fmt.Errorf("artifact %q: %w", r.Artifact, err)
		}
		zr, err := zip.OpenReader(filepath.Join(outDir, filepath.FromSlash(r.Artifact)))
		if err != nil {
			return nil, err
		}
		files := append([]*zip.File(nil), zr.File...)
		sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
		for _, f := range files {
			if !strings.HasSuffix(f.Name, ".class") || strings.HasPrefix(f.Name, "META-INF/") {
				continue
			}
			raw, err := readZip(f)
			if err != nil {
				zr.Close()
				return nil, fmt.Errorf("%s!%s: %w", r.Artifact, f.Name, err)
			}
			ci, err := parseClass(raw)
			if err != nil {
				zr.Close()
				return nil, fmt.Errorf("%s!%s: %w", r.Artifact, f.Name, err)
			}
			sum := sha256.Sum256(raw)
			classSHA := "sha256:" + hex.EncodeToString(sum[:])
			var srcPath, srcSHA *string
			binding := BindingUnavailable
			if ci.SourceFile != "" && !strings.ContainsAny(ci.SourceFile, `/\`) {
				pkg := ""
				if i := strings.LastIndexByte(ci.Name, '.'); i >= 0 {
					pkg = strings.ReplaceAll(ci.Name[:i], ".", "/")
				}
				rel := path.Join(r.Path, pkg, ci.SourceFile)
				h, ok := fileHash[rel]
				if !ok {
					if h, err = fileSHA256(filepath.Join(checkout, filepath.FromSlash(rel))); err != nil && !errors.Is(err, os.ErrNotExist) {
						zr.Close()
						return nil, err
					}
					fileHash[rel] = h
				}
				if h != "" {
					srcPath, srcSHA, binding = &rel, &h, BindingBuildVerified
				} else {
					declared := path.Join(pkg, ci.SourceFile)
					srcPath, binding = &declared, BindingDeclared
				}
			}
			for _, m := range ci.Methods {
				e := Entry{Artifact: r.Artifact, Class: ci.Name, ClassSHA256: classSHA, Name: m.Name, Descriptor: m.Descriptor,
					Path: srcPath, SourceSHA256: srcSHA, Binding: binding}
				if m.LineStart > 0 {
					lo, hi := m.LineStart, m.LineEnd
					e.LineStart, e.LineEnd = &lo, &hi
				}
				ix.Entries = append(ix.Entries, e)
			}
		}
		zr.Close()
	}
	ix.reindex()
	return ix, nil
}

func (ix *Index) reindex() {
	ix.byHash, ix.byName = map[string]int{}, map[string][]int{}
	for i, e := range ix.Entries {
		ix.byHash[methodKey(e.ClassSHA256, e.Name, e.Descriptor)] = i
		k := methodKey(e.Class, e.Name, e.Descriptor)
		ix.byName[k] = append(ix.byName[k], i)
	}
}

// Load reads a saved index.
func Load(file string) (*Index, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var ix Index
	if err := json.Unmarshal(raw, &ix); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if ix.SchemaVersion != Schema {
		return nil, fmt.Errorf("%s: schema %q, want %q", file, ix.SchemaVersion, Schema)
	}
	ix.reindex()
	return &ix, nil
}

// Save writes the index; the bytes depend only on its content.
func (ix *Index) Save(file string) error {
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(b, '\n'), 0o644)
}

// Method identifies a method as Ariadne reports it. ClassSHA256 is empty
// when Ariadne has no class file for it (an external method).
type Method struct {
	Class       string `json:"class"`
	Name        string `json:"name"`
	Descriptor  string `json:"descriptor"`
	ClassSHA256 string `json:"class_sha256,omitempty"`
}

// Lookup finds the entry for m: by class file hash when m has one, else by
// name when exactly one indexed class file has that name.
func (ix *Index) Lookup(m Method) (*Entry, bool) {
	if m.ClassSHA256 != "" {
		i, ok := ix.byHash[methodKey(m.ClassSHA256, m.Name, m.Descriptor)]
		if !ok {
			return nil, false
		}
		return &ix.Entries[i], true
	}
	is := ix.byName[methodKey(m.Class, m.Name, m.Descriptor)]
	if len(is) != 1 {
		return nil, false
	}
	return &ix.Entries[is[0]], true
}

// AriadneSource is the contract's Source record.
type AriadneSource struct {
	Path         *string `json:"path"`
	LineStart    *int    `json:"line_start"`
	LineEnd      *int    `json:"line_end"`
	SourceSHA256 *string `json:"source_sha256"`
	Binding      string  `json:"binding"`
}

// Bases of a Location.
const (
	BasisAriadne   = "ariadne"   // only Ariadne's Source record
	BasisTekmerion = "tekmerion" // only this index
	BasisBoth      = "ariadne+tekmerion"
	BasisNone      = "none"
)

// Location is where a method's source is, and on what basis.
type Location struct {
	Method       Method   `json:"method"`
	Artifact     string   `json:"artifact,omitempty"`
	Path         *string  `json:"path"`
	LineStart    *int     `json:"line_start"`
	LineEnd      *int     `json:"line_end"`
	SourceSHA256 *string  `json:"source_sha256"`
	Binding      string   `json:"binding"`
	Basis        string   `json:"basis"`
	Conflicts    []string `json:"conflicts,omitempty"`
}

// Resolve locates m's source. a is Ariadne's Source record for the method,
// or nil. When Ariadne and the index disagree on the file, its hash or the
// lines, the location lists the conflicts and its binding is unavailable,
// so nothing cites it as verified.
func (ix *Index) Resolve(m Method, a *AriadneSource) Location {
	loc := Location{Method: m, Binding: BindingUnavailable, Basis: BasisNone}
	own, haveOwn := ix.Lookup(m)
	ariadneUseful := a != nil && (a.Path != nil || a.LineStart != nil)
	if haveOwn {
		loc.Artifact = own.Artifact
		loc.Path, loc.LineStart, loc.LineEnd, loc.SourceSHA256, loc.Binding = own.Path, own.LineStart, own.LineEnd, own.SourceSHA256, own.Binding
		loc.Basis = BasisTekmerion
	}
	if !ariadneUseful {
		return loc
	}
	if !haveOwn {
		loc.Path, loc.LineStart, loc.LineEnd, loc.SourceSHA256, loc.Binding = a.Path, a.LineStart, a.LineEnd, a.SourceSHA256, a.Binding
		loc.Basis = BasisAriadne
		return loc
	}
	loc.Basis = BasisBoth
	if a.Path != nil {
		if own.Path == nil || !samePath(*own.Path, *a.Path) {
			loc.Conflicts = append(loc.Conflicts, fmt.Sprintf("path: ariadne %q, index %s", *a.Path, strOrNull(own.Path)))
		}
	}
	if a.SourceSHA256 != nil && own.SourceSHA256 != nil && *a.SourceSHA256 != *own.SourceSHA256 {
		loc.Conflicts = append(loc.Conflicts, fmt.Sprintf("source_sha256: ariadne %s, index %s", *a.SourceSHA256, *own.SourceSHA256))
	}
	if a.LineStart != nil {
		if own.LineStart == nil || *a.LineStart != *own.LineStart || intOr0(a.LineEnd) != intOr0(own.LineEnd) {
			loc.Conflicts = append(loc.Conflicts, fmt.Sprintf("lines: ariadne %s, index %s", lines(a.LineStart, a.LineEnd), lines(own.LineStart, own.LineEnd)))
		}
	}
	if len(loc.Conflicts) > 0 {
		loc.Binding = BindingUnavailable
		return loc
	}
	if loc.LineStart == nil {
		loc.LineStart, loc.LineEnd = a.LineStart, a.LineEnd
	}
	if loc.SourceSHA256 == nil && a.SourceSHA256 != nil {
		loc.SourceSHA256 = a.SourceSHA256
	}
	// The stronger of the two bindings stands; both agree on everything
	// they both state.
	if a.Binding == BindingBuildVerified {
		loc.Binding = BindingBuildVerified
	}
	return loc
}

// samePath reports whether Ariadne's path names the indexed file. Ariadne
// reports the path within the package tree or within its -sources
// directory; the index path additionally starts with the source root.
func samePath(indexed, ariadne string) bool {
	ariadne = strings.TrimPrefix(path.Clean(filepath.ToSlash(ariadne)), "./")
	return indexed == ariadne || strings.HasSuffix(indexed, "/"+ariadne)
}

func strOrNull(s *string) string {
	if s == nil {
		return "null"
	}
	return fmt.Sprintf("%q", *s)
}

func intOr0(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func lines(a, b *int) string {
	if a == nil {
		return "null"
	}
	return fmt.Sprintf("%d-%d", *a, intOr0(b))
}

func cleanRel(p string) error {
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return errors.New("must be a clean relative slash path")
	}
	return nil
}

func readZip(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func fileSHA256(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
