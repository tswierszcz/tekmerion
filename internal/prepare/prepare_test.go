package prepare

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

// gitRepo makes a repository holding the source index sample (sources and
// a prebuilt jar, so the build needs no JDK) and returns it and its commit.
func gitRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	sample := "../../testdata/sourceindex"
	for _, f := range []string{"src/ex/pkg/Sample.java", "sample.jar"} {
		raw, err := os.ReadFile(filepath.Join(sample, f))
		if err != nil {
			t.Fatal(err)
		}
		to := filepath.Join(dir, "lib", f)
		os.MkdirAll(filepath.Dir(to), 0o755)
		if err := os.WriteFile(to, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("not exported\n"), 0o644)
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
			"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("add", ".")
	run("commit", "-q", "-m", "sample")
	return dir, run("rev-parse", "HEAD")
}

func project(rev string) *manifest.Project {
	return &manifest.Project{
		SchemaVersion: manifest.ProjectSchema,
		Target: manifest.Target{Repository: "https://example.invalid/sample", Revision: rev, Paths: []string{"lib"},
			SourceRoots: []sourceindex.Root{{Path: "lib/src", Artifact: "lib.jar"}}},
		Build: manifest.Recipe{Network: manifest.NetworkNone, Steps: []manifest.Step{
			{Name: "jar", Argv: []string{"cp", "lib/sample.jar", "${OUT}/lib.jar"}},
			{Name: "deps", Argv: []string{"mkdir", "${OUT}/deps"}},
			{Name: "dep", Argv: []string{"cp", "lib/sample.jar", "${OUT}/deps/b-dep-1.0.jar"}},
			{Name: "dep2", Argv: []string{"cp", "lib/sample.jar", "${OUT}/deps/a-dep-1.0.jar"}},
			{Name: "deps-list", Argv: []string{"sh", "-c", `printf 'x:a-dep:jar:1.0:compile\nx:b-dep:jar:1.0:compile\n' > "$$1"`, "-", "${OUT}/deps.txt"}},
			{Name: "net", Argv: []string{"sh", "-c", `cat /proc/net/dev > "$$1"`, "-", "${OUT}/net.txt"}},
		}, Outputs: manifest.Outputs{App: "lib.jar", Deps: "deps", DepsList: "deps.txt"}},
		Scenario: manifest.Scenario{Roots: "api"},
	}
}

func needNetns(t *testing.T) {
	if exec.Command("unshare", "--user", "--map-current-user", "--net", "--", "true").Run() != nil {
		t.Skip("no unprivileged network namespace here")
	}
}

func prep(t *testing.T, repo string, p *manifest.Project, o Options) (*Result, error) {
	t.Helper()
	raw, _ := json.Marshal(p)
	o.Project, o.ProjectRaw, o.Checkout = p, raw, repo
	if o.Work == "" {
		o.Work = filepath.Join(t.TempDir(), "work")
	}
	return Prepare(context.Background(), o)
}

func TestPrepare(t *testing.T) {
	needNetns(t)
	repo, rev := gitRepo(t)
	res, err := prep(t, repo, project(rev), Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Run
	if r.Source.Commit != rev || r.Source.Files != 2 || r.Source.CommitTime != 1767225600 || r.Source.GitTrees["lib"] == "" {
		t.Fatalf("source %+v", r.Source)
	}
	if _, err := os.Stat(filepath.Join(res.SourceDir, "unrelated.txt")); err == nil {
		t.Fatal("a path outside target.paths was exported")
	}
	// network "none": the build saw only loopback.
	net, _ := os.ReadFile(filepath.Join(res.OutDir, "net.txt"))
	if strings.Count(string(net), "\n") != 3 || !strings.Contains(string(net), "lo:") {
		t.Fatalf("build saw interfaces:\n%s", net)
	}
	if r.Build.NetworkEnforcement != "netns" || len(r.Build.Steps) != 6 || r.Build.Steps[0].Argv[0] != "unshare" {
		t.Fatalf("build %+v", r.Build)
	}
	if r.Build.Env["SOURCE_DATE_EPOCH"] != "1767225600" || r.Build.Env["HOME"] != "${WORK}/home" {
		t.Fatalf("env %v", r.Build.Env)
	}
	jar, _ := fileSHA("../../testdata/sourceindex/sample.jar")
	a := r.Artifacts
	if a.App.SHA256 != jar || strings.Join(a.Classpath, " ") != "lib.jar deps/a-dep-1.0.jar deps/b-dep-1.0.jar" || a.DepsList == nil {
		t.Fatalf("artifacts %+v", a)
	}
	if r.SourceIndex.Methods == 0 || r.SourceIndex.Located != r.SourceIndex.Methods || r.Analysis != nil {
		t.Fatalf("index %+v analysis %+v", r.SourceIndex, r.Analysis)
	}
	if fi, _ := os.Stat(filepath.Join(res.SourceDir, "lib")); fi.Mode().Perm()&0o200 == 0 {
		t.Fatal("source tree left read-only")
	}
	saved, err := manifest.LoadRun(filepath.Join(res.Work, "run-manifest.json"))
	if err != nil || saved.Artifacts.ClasspathSHA256 != a.ClasspathSHA256 {
		t.Fatalf("saved manifest: %v", err)
	}

	// A second preparation records the same identities.
	res2, err := prep(t, repo, project(rev), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !sameBinding(r, res2.Run) {
		t.Fatal("two preparations of one revision differ")
	}
}

// sameBinding compares everything but the preparation time, durations and
// the bundle manifest's hash (it carries Ariadne's created_at; the
// analysis_id is the identity hash and is compared).
func sameBinding(a, b *manifest.Run) bool {
	norm := func(r *manifest.Run) []byte {
		c := *r
		c.PreparedAt = time.Time{}
		if r.Analysis != nil {
			an := *r.Analysis
			an.ManifestSHA256 = ""
			c.Analysis = &an
		}
		c.Build.Steps = append([]manifest.StepRun(nil), r.Build.Steps...)
		for i := range c.Build.Steps {
			c.Build.Steps[i].Duration = ""
		}
		raw, _ := json.Marshal(c)
		return raw
	}
	return bytes.Equal(norm(a), norm(b))
}

func TestPrepareRefuses(t *testing.T) {
	needNetns(t)
	repo, rev := gitRepo(t)

	p := project(rev)
	p.Build.Network = manifest.NetworkAllowed
	if _, err := prep(t, repo, p, Options{}); err == nil || !strings.Contains(err.Error(), "network") {
		t.Fatalf("network recipe without permission: %v", err)
	}

	p = project(strings.Repeat("0", 40))
	if _, err := prep(t, repo, p, Options{}); err == nil || !strings.Contains(err.Error(), "does not have revision") {
		t.Fatalf("absent revision: %v", err)
	}

	p = project(rev)
	p.Build.Steps = append(p.Build.Steps, manifest.Step{Name: "touch-src", Argv: []string{"touch", "${SRC}/lib/new"}})
	if _, err := prep(t, repo, p, Options{}); err == nil || !strings.Contains(err.Error(), "touch-src") {
		t.Fatalf("a build writing its source: %v", err)
	}

	p = project(rev)
	p.Build.Steps[4].Argv = []string{"sh", "-c", `echo junk > "$$1"`, "-", "${OUT}/deps.txt"}
	if _, err := prep(t, repo, p, Options{}); err == nil || !strings.Contains(err.Error(), "deps_list") {
		t.Fatalf("bad deps list: %v", err)
	}

	work := filepath.Join(t.TempDir(), "w")
	os.Mkdir(work, 0o755)
	if _, err := prep(t, repo, project(rev), Options{Work: work}); err == nil {
		t.Fatal("existing work directory reused")
	}
}

func TestPrepareAllowedNetwork(t *testing.T) {
	repo, rev := gitRepo(t)
	p := project(rev)
	p.Build.Network = manifest.NetworkAllowed
	res, err := prep(t, repo, p, Options{AllowNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Build.Network != manifest.NetworkAllowed || res.Run.Build.NetworkEnforcement != "none" || res.Run.Build.Steps[0].Argv[0] != "cp" {
		t.Fatalf("%+v", res.Run.Build)
	}
}
