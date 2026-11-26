package prepare

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func diffPatch(t *testing.T, rel string, before, after []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	for side, b := range map[string][]byte{"a": before, "b": after} {
		p := filepath.Join(dir, side, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, b, 0o644)
	}
	cmd := exec.Command("git", "diff", "--no-index", "--no-prefix", "--", filepath.Join("a", rel), filepath.Join("b", rel))
	cmd.Dir = dir
	out, _ := cmd.Output() // exit status 1 means "differs"
	if len(out) == 0 {
		t.Fatal("empty diff")
	}
	return out
}

func TestBuildVariant(t *testing.T) {
	needNetns(t)
	repo, rev := gitRepo(t)
	res, err := prep(t, repo, project(rev), Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(res.Work)
	if err != nil {
		t.Fatal(err)
	}
	rel := "lib/src/ex/pkg/Sample.java"
	orig, err := os.ReadFile(filepath.Join(res.SourceDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	patch := diffPatch(t, rel, orig, append([]byte("// corrected\n"), orig...))
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "variant")
	r, err := BuildVariant(ctx, v, patch, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changed) != 1 || r.Changed[0].Path != rel || r.Changed[0].Before == r.Changed[0].After || r.BaseTreeSHA256 != v.Run.Source.TreeSHA256 || r.TreeSHA256 == r.BaseTreeSHA256 {
		t.Fatalf("variant %+v", r)
	}
	if len(r.Build.Steps) != len(v.Project.Build.Steps) || r.Build.NetworkEnforcement != "netns" || r.Artifacts.App.SHA256 == "" {
		t.Fatalf("variant build %+v", r.Build)
	}
	if err := CheckVariant(dir, r, v.Project.Build.Outputs); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(res.Work); err != nil {
		t.Fatal("original preparation changed: ", err)
	}
	if _, err := BuildVariant(ctx, v, patch, dir, nil); err == nil {
		t.Fatal("existing variant directory reused")
	}
	os.Chmod(filepath.Join(dir, "out", "lib.jar"), 0o644)
	if err := os.WriteFile(filepath.Join(dir, "out", "lib.jar"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckVariant(dir, r, v.Project.Build.Outputs); err == nil {
		t.Fatal("tampered variant output accepted")
	}
	for name, p := range map[string][]byte{
		"escape":       []byte(strings.ReplaceAll(string(patch), rel, "../outside.java")),
		"not applying": []byte(strings.ReplaceAll(string(patch), " package", " pkg-does-not-exist")),
		"empty":        nil,
	} {
		if _, err := BuildVariant(ctx, v, p, filepath.Join(t.TempDir(), "v"), nil); err == nil {
			t.Errorf("%s patch accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(res.Work), "outside.java")); err == nil {
		t.Fatal("patch wrote outside the variant tree")
	}
}
