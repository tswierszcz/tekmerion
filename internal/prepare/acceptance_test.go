package prepare

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

// TM1 acceptance (IMPLEMENTATION_PLAN.md section 8): rebuild the pinned
// control library from source and bind the source, artifact and bundle
// hashes. The target is Ariadne's research control library
// (testdata/research at the revision in testdata/control/project.json).
//
//	(cd $ARIADNE_SRC && go build -o bin/ariadne ./cmd/ariadne)
//	ARIADNE_SRC=/path/to/ariadne go test ./internal/prepare -run Acceptance -v
//
// ARIADNE_SRC must be a git checkout that has the pinned revision; the
// build exports it from git, not from the working tree. ARIADNE_BIN
// overrides the binary. The build needs java (JDK 11+ with jdk.compiler).
func TestAcceptanceControlLibrary(t *testing.T) {
	src := os.Getenv("ARIADNE_SRC")
	if src == "" {
		t.Skip("ARIADNE_SRC not set: TM1 acceptance skipped")
	}
	bin := os.Getenv("ARIADNE_BIN")
	if bin == "" {
		bin = filepath.Join(src, "bin", "ariadne")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("ariadne binary: %v", err)
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Fatal("java is not on PATH")
	}
	needNetns(t)
	p, raw, err := manifest.LoadProject("../../testdata/control/project.json")
	if err != nil {
		t.Fatal(err)
	}
	rev := p.Target.Revision
	ctx := context.Background()
	tmp := t.TempDir()

	runs := make([]*Result, 2)
	for i := range runs {
		runs[i], err = Prepare(ctx, Options{Project: p, ProjectRaw: raw, Checkout: src, Work: filepath.Join(tmp, fmt.Sprintf("w%d", i)), Ariadne: bin})
		if err != nil {
			t.Fatalf("preparation %d: %v", i, err)
		}
	}
	r := runs[0].Run
	t.Logf("commit %s source %s app %s classpath %s analysis %s ariadne %s",
		r.Source.Commit, r.Source.TreeSHA256, r.Artifacts.App.SHA256, r.Artifacts.ClasspathSHA256, r.Analysis.AnalysisID, r.Analysis.AriadneToolVersion)

	// 1. Reproducible: both preparations bind the same identities.
	if !sameBinding(r, runs[1].Run) {
		a, _ := json.MarshalIndent(r, "", " ")
		b, _ := json.MarshalIndent(runs[1].Run, "", " ")
		t.Fatalf("two preparations differ:\n%s\n---\n%s", a, b)
	}

	// 2. The rebuilt artifacts are the jars committed at the revision.
	committed := filepath.Join(tmp, "committed")
	for _, f := range append([]manifest.File{r.Artifacts.App}, r.Artifacts.Deps...) {
		blob, err := exec.Command("git", "-C", src, "show", rev+":testdata/research/"+f.Path).Output()
		if err != nil {
			t.Fatalf("committed %s: %v", f.Path, err)
		}
		if got := sha256Hex(blob); got != f.SHA256 {
			t.Errorf("%s rebuilt %s, committed %s", f.Path, f.SHA256, got)
		}
		to := filepath.Join(committed, f.Path)
		os.MkdirAll(filepath.Dir(to), 0o755)
		os.WriteFile(to, blob, 0o644)
	}
	blob, _ := exec.Command("git", "-C", src, "show", rev+":testdata/research/deps.txt").Output()
	if sha256Hex(blob) != r.Artifacts.DepsList.SHA256 {
		t.Errorf("deps.txt differs from the committed one")
	}
	os.WriteFile(filepath.Join(committed, "deps.txt"), blob, 0o644)

	// 3. The bundle is bound to the artifacts: indexing the committed jars
	// with the same scenario yields the same analysis_id.
	ir, err := ariadne.Index(ctx, bin, ariadne.IndexOptions{App: filepath.Join(committed, "lib.jar"), Deps: filepath.Join(committed, "deps"),
		DepsList: filepath.Join(committed, "deps.txt"), Roots: p.Scenario.Roots, Profile: p.Scenario.Profile, Out: filepath.Join(tmp, "committed-bundle"),
		Sources: sourcesArg(r, runs[0])})
	if err != nil {
		t.Fatal(err)
	}
	if ir.Bundle.AnalysisID != r.Analysis.AnalysisID {
		t.Errorf("analysis of the committed jars %s, of the rebuild %s", ir.Bundle.AnalysisID, r.Analysis.AnalysisID)
	}

	// 4. Source binding: every method of the library and its dependencies
	// that Ariadne lists resolves to its source file and lines, with
	// Ariadne's Source record (lines today, the path with -sources) and the
	// index agreeing.
	cli := &ariadne.CLI{Binary: bin, Bundle: runs[0].Bundle.Dir, Evidence: ariadne.Recorder{Root: filepath.Join(tmp, "evidence")}}
	locs := map[string]sourceindex.Location{}
	withPath, withHash, libMethods := 0, 0, 0
	var cursor any
	for page := 0; ; page++ {
		req, _ := json.Marshal(map[string]any{"schema_version": ariadne.QuerySchema, "analysis_id": r.Analysis.AnalysisID,
			"request_id": fmt.Sprintf("methods-%d", page), "operation": "methods", "limits": map[string]any{"max_records": 10}, "cursor": cursor})
		res, err := cli.Query(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Records []struct {
				Method sourceindex.Method         `json:"method"`
				Source *sourceindex.AriadneSource `json:"source"`
				Body   string                     `json:"body"`
			} `json:"records"`
			Page struct {
				NextCursor *string `json:"next_cursor"`
			} `json:"page"`
		}
		if err := json.Unmarshal(res.RawResponse, &doc); err != nil {
			t.Fatal(err)
		}
		for _, rec := range doc.Records {
			if !strings.HasPrefix(rec.Method.Class, "fx.") {
				continue
			}
			if rec.Source != nil && rec.Source.Path != nil {
				withPath++
			}
			if rec.Source != nil && rec.Source.SourceSHA256 != nil {
				withHash++
			}
			if strings.HasPrefix(rec.Method.Class, "fx.research.") {
				libMethods++
			}
			loc := runs[0].Index.Resolve(rec.Method, rec.Source)
			key := rec.Method.Class + "#" + rec.Method.Name + rec.Method.Descriptor
			locs[key] = loc
			if loc.Binding != sourceindex.BindingBuildVerified || len(loc.Conflicts) > 0 || loc.Path == nil {
				t.Errorf("%s: %+v", key, loc)
			}
		}
		if doc.Page.NextCursor == nil {
			break
		}
		cursor = *doc.Page.NextCursor
	}
	want := map[string]string{
		"fx.research.Extractor#writeEntry(Ljava/nio/file/Path;[B)V": "testdata/research/lib/fx/research/Extractor.java",
		"fx.research.internal.Cleaner#wipe(Ljava/nio/file/Path;)V":  "testdata/research/lib/fx/research/internal/Cleaner.java",
		// the selected (1.0) copy of Paths2, matched by class hash
		"fx.dep.Paths2#resolve(Ljava/nio/file/Path;Ljava/lang/String;)Ljava/nio/file/Path;": "testdata/research/depold/fx/dep/Paths2.java",
	}
	for k, path := range want {
		loc, ok := locs[k]
		if !ok {
			t.Errorf("%s not listed by methods", k)
			continue
		}
		if *loc.Path != path || loc.LineStart == nil {
			t.Errorf("%s at %s %v, want %s", k, *loc.Path, loc.LineStart, path)
		}
		t.Logf("%s -> %s:%d-%d (%s, %s)", k, *loc.Path, *loc.LineStart, *loc.LineEnd, loc.Binding, loc.Basis)
	}
	if len(locs) == 0 {
		t.Fatal("no fx.* methods listed")
	}
	// With an Ariadne that reports paths (-sources, RI4), every method had
	// a path and every library method a hash, and both were cross-checked.
	t.Logf("ariadne source records: %d methods, %d with path, %d with source_sha256 (sources_flag %v)", len(locs), withPath, withHash, r.Analysis.SourcesFlag)
	if r.Analysis.SourcesFlag && (withPath != len(locs) || withHash < libMethods) {
		t.Errorf("-sources passed but only %d/%d paths and %d/%d library hashes", withPath, len(locs), withHash, libMethods)
	}
}

// sourcesArg repeats the -sources argument the preparation used.
func sourcesArg(r *manifest.Run, res *Result) string {
	if !r.Analysis.SourcesFlag {
		return ""
	}
	return filepath.Join(res.SourceDir, "testdata/research/lib")
}
