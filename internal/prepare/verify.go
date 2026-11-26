package prepare

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

// Verified is a preparation whose declared inputs and outputs still match.
// It does not execute target code or rebuild the target.
type Verified struct {
	Gaps        []string
	Run         *manifest.Run
	Project     *manifest.Project
	Index       *sourceindex.Index
	RawManifest []byte
	RawIndex    []byte
	Work        string
}

// ReadFile reads a bounded regular member through an OS-confined directory
// handle. Static symlinks are rejected, including directory components.
func ReadFile(dir, relative string, limit int64) ([]byte, error) {
	if relative == "" || !filepath.IsLocal(relative) || filepath.ToSlash(relative) != relative || path.Clean(relative) != relative {
		return nil, fmt.Errorf("unsafe preparation member %q", relative)
	}
	rootInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("preparation read root is not a regular directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	current := ""
	for _, part := range splitPath(relative) {
		current = path.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink preparation member %q", relative)
		}
	}
	info, err := root.Stat(relative)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("preparation member is not a bounded regular file: %s", relative)
	}
	f, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("preparation member changed type/size")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("preparation member exceeds byte limit")
	}
	return raw, nil
}
func splitPath(relative string) []string {
	var parts []string
	for relative != "." {
		dir, file := path.Split(relative)
		parts = append([]string{file}, parts...)
		if dir == "" {
			break
		}
		relative = path.Clean(dir)
	}
	return parts
}
func Verify(work string) (*Verified, error) {
	absolute, err := filepath.Abs(work)
	if err != nil {
		return nil, err
	}
	raw, err := ReadFile(absolute, "run-manifest.json", 4<<20)
	if err != nil {
		return nil, err
	}
	var run manifest.Run
	if err := jsonx.Decode(raw, &run, false); err != nil {
		return nil, err
	}
	if run.SchemaVersion != manifest.RunSchema {
		return nil, fmt.Errorf("unsupported preparation manifest")
	}
	var project manifest.Project
	if err := jsonx.Decode(run.Project, &project, false); err != nil {
		return nil, err
	}
	if err := project.Validate(); err != nil {
		return nil, err
	}
	gaps := []string{}
	if len(run.ProjectOriginal) > 0 {
		if sha256Hex(run.ProjectOriginal) != run.ProjectSHA256 {
			return nil, fmt.Errorf("original project-file hash mismatch")
		}
		var original, embedded any
		if err := jsonx.Decode(run.ProjectOriginal, &original, true); err != nil {
			return nil, err
		}
		if err := jsonx.Decode(run.Project, &embedded, true); err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(original, embedded) {
			return nil, fmt.Errorf("embedded project differs from original bytes")
		}
	} else {
		gaps = append(gaps, "legacy preparation lacks original project bytes; its project-file hash cannot be independently rechecked")
	}
	if run.Source.Commit != project.Target.Revision || run.Source.Repository != project.Target.Repository {
		return nil, fmt.Errorf("project/source identity mismatch")
	}
	for _, name := range []string{"src", "out", "bundle"} {
		if name == "bundle" && run.Analysis == nil {
			continue
		}
		info, err := os.Lstat(filepath.Join(absolute, name))
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("prepared %s root is not a regular directory", name)
		}
	}
	sourceSHA, count, err := treeHash(filepath.Join(absolute, "src"))
	if err != nil {
		return nil, err
	}
	if sourceSHA != run.Source.TreeSHA256 || count != run.Source.Files {
		return nil, fmt.Errorf("prepared source tree changed")
	}
	if run.Build.Network != project.Build.Network || len(run.Build.Steps) != len(project.Build.Steps) {
		return nil, fmt.Errorf("prepared build recipe/outcome mismatch")
	}
	for i, step := range run.Build.Steps {
		if step.Name != project.Build.Steps[i].Name || step.Exit != 0 {
			return nil, fmt.Errorf("prepared build has failed or mismatched step")
		}
	}
	if run.Artifacts.App.Path != project.Build.Outputs.App {
		return nil, fmt.Errorf("prepared app differs from recipe")
	}
	files := append([]manifest.File{run.Artifacts.App}, run.Artifacts.Deps...)
	if run.Artifacts.DepsList != nil {
		files = append(files, *run.Artifacts.DepsList)
	}
	for _, file := range files {
		// Artifact bytes are hashed as a stream by preparation; the bounded read
		// here also rejects escapes and special files before downstream parsing.
		data, err := ReadFile(filepath.Join(absolute, "out"), file.Path, 256<<20)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != file.Size || sha256Hex(data) != file.SHA256 {
			return nil, fmt.Errorf("prepared artifact changed: %s", file.Path)
		}
	}
	classpath := []string{}
	identities := []string{}
	for _, file := range append([]manifest.File{run.Artifacts.App}, run.Artifacts.Deps...) {
		classpath = append(classpath, file.Path)
		identities = append(identities, file.SHA256+" "+file.Path)
	}
	if !reflect.DeepEqual(classpath, run.Artifacts.Classpath) || sha256Hex([]byte(strings.Join(identities, "\n")+"\n")) != run.Artifacts.ClasspathSHA256 {
		return nil, fmt.Errorf("prepared classpath identity mismatch")
	}
	if run.SourceIndex.File.Path != "source-index.json" {
		return nil, fmt.Errorf("unexpected source-index path")
	}
	indexRaw, err := ReadFile(absolute, "source-index.json", 16<<20)
	if err != nil {
		return nil, err
	}
	if sha256Hex(indexRaw) != run.SourceIndex.File.SHA256 || int64(len(indexRaw)) != run.SourceIndex.File.Size {
		return nil, fmt.Errorf("source index changed")
	}
	var index sourceindex.Index
	if err := jsonx.Decode(indexRaw, &index, false); err != nil {
		return nil, err
	}
	if index.SchemaVersion != sourceindex.Schema || len(index.Entries) != run.SourceIndex.Methods {
		return nil, fmt.Errorf("source index identity/count mismatch")
	}
	if run.Analysis != nil {
		if run.Analysis.Bundle != "bundle" || run.Analysis.Roots != project.Scenario.Roots {
			return nil, fmt.Errorf("prepared analysis scenario mismatch")
		}
		bundleManifest, err := ReadFile(absolute, "bundle/manifest.json", 2<<20)
		if err != nil {
			return nil, err
		}
		bundleIdentity, err := ReadFile(absolute, "bundle/identity.json", 16<<20)
		if err != nil {
			return nil, err
		}
		if sha256Hex(bundleManifest) != run.Analysis.ManifestSHA256 || sha256Hex(bundleIdentity) != run.Analysis.IdentitySHA256 || sha256Hex(bundleIdentity) != run.Analysis.AnalysisID {
			return nil, fmt.Errorf("prepared bundle identity changed")
		}
	}
	located := 0
	for _, entry := range index.Entries {
		if entry.Binding == sourceindex.BindingBuildVerified {
			located++
		}
	}
	if located != run.SourceIndex.Located {
		return nil, fmt.Errorf("prepared source binding count mismatch")
	}
	// Parse initializes exact class-hash lookup maps after hash validation.
	loaded, err := sourceindex.Parse(indexRaw)
	if err != nil {
		return nil, err
	}
	return &Verified{Gaps: gaps, Run: &run, Project: &project, Index: loaded, RawManifest: raw, RawIndex: indexRaw, Work: absolute}, nil
}
