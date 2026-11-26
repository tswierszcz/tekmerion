package ariadne

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Integration with the real Ariadne binary on its control library
// testdata/research (expected results in testdata/research/EXPECTED.MD).
//
//	(cd $ARIADNE_SRC && go build -o bin/ariadne ./cmd/ariadne)
//	ARIADNE_SRC=/path/to/ariadne go test ./internal/ariadne -run Ariadne
//
// ARIADNE_BIN overrides the binary (default $ARIADNE_SRC/bin/ariadne).
// Without ARIADNE_SRC the test is skipped.

func ariadneEnv(t *testing.T) (bin, data string) {
	t.Helper()
	src := os.Getenv("ARIADNE_SRC")
	if src == "" {
		t.Skip("ARIADNE_SRC not set: real Ariadne integration skipped")
	}
	bin = os.Getenv("ARIADNE_BIN")
	if bin == "" {
		bin = filepath.Join(src, "bin", "ariadne")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("ariadne binary: %v (build it with: go build -o bin/ariadne ./cmd/ariadne)", err)
	}
	data = filepath.Join(src, "testdata", "research")
	if _, err := os.Stat(filepath.Join(data, "lib.jar")); err != nil {
		t.Fatalf("control library: %v", err)
	}
	return bin, data
}

type component struct {
	InstanceID string `json:"instance_id"`
	Location   string `json:"location"`
}

func components(t *testing.T, bundle string) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(bundle, "components.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c component
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		out[c.Location] = c.InstanceID
	}
	return out
}

func request(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// evidenceMethods maps the node ids in a response's evidence to
// Class#nameDescriptor.
func evidenceMethods(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	var doc struct {
		Evidence []struct {
			RecordType string `json:"record_type"`
			NodeID     string `json:"node_id"`
			Method     struct {
				Class, Name, Descriptor string
			} `json:"method"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range doc.Evidence {
		if e.RecordType == "node" {
			out[e.NodeID] = e.Method.Class + "#" + e.Method.Name + e.Method.Descriptor
		}
	}
	return out
}

func TestAriadneIndexRequiresRoots(t *testing.T) {
	if _, err := Index(context.Background(), "ariadne", IndexOptions{Out: t.TempDir() + "/b"}); err == nil {
		t.Fatal("index without roots accepted")
	}
	if _, err := Index(context.Background(), "ariadne", IndexOptions{Roots: "api", Scope: "some", Out: t.TempDir() + "/b"}); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

func TestAriadneControlLibrary(t *testing.T) {
	bin, data := ariadneEnv(t)
	// "" passes no -scope (the producer default, every graph node), which
	// also works with Ariadne builds that predate -scope.
	for _, scope := range []string{"", "reachable"} {
		t.Run("scope="+scope, func(t *testing.T) { controlLibrary(t, bin, data, scope) })
	}
}

func controlLibrary(t *testing.T, bin, data, scope string) {
	ctx := context.Background()
	work := t.TempDir()
	emptyCache := filepath.Join(work, "empty-cache")
	if err := os.Mkdir(emptyCache, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := IndexOptions{App: filepath.Join(data, "lib.jar"), Deps: filepath.Join(data, "deps"), DepsList: filepath.Join(data, "deps.txt"),
		Roots: "api", Profile: "generic", Scope: scope, CacheDir: emptyCache, Out: filepath.Join(work, "bundle")}
	ix, err := Index(ctx, bin, opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, ix.Stderr)
	}
	b := ix.Bundle
	wantScope := scope
	if wantScope == "" {
		wantScope = "all"
	}
	if !strings.HasPrefix(b.AnalysisID, "sha256:") || b.RootsMode != "api" || b.Scope != wantScope {
		t.Fatalf("bundle %+v", b)
	}
	t.Logf("ariadne %s, scope %s, analysis %s", b.ToolVersion, scope, b.AnalysisID)
	// A second index of the same input has the same analysis id.
	opts.Out = filepath.Join(work, "bundle2")
	if ix2, err := Index(ctx, bin, opts); err != nil || ix2.Bundle.AnalysisID != b.AnalysisID {
		t.Fatalf("re-index: %v", err)
	}
	// An existing bundle is never overwritten: exit 2 from the producer.
	if ix3, err := Index(ctx, bin, opts); err == nil || ix3.Exit != 2 {
		t.Fatalf("index over an existing bundle: %v", err)
	}

	comp := components(t, b.Dir)
	lib, v1, v2 := comp["app:lib.jar"], comp["deps:fx-dep-1.0.jar"], comp["deps:fx-dep-2.0.jar"]
	if lib == "" || v1 == "" || v2 == "" {
		t.Fatalf("components %v", comp)
	}
	evidence := Recorder{Root: filepath.Join(work, "evidence")}
	cli := &CLI{Binary: bin, Bundle: b.Dir, Evidence: evidence}

	const P = "Ljava/nio/file/Path;"
	type want struct {
		id, inst, class, name, desc string
		resolution, search, model   string
		entries                     []string // root methods, sorted; nil: not checked
	}
	extract := "fx.research.Extractor#extract(Ljava/io/InputStream;" + P + ")V"
	saveSBP := "fx.research.Extractor#save(Ljava/lang/String;[B" + P + ")V"
	saveB := "fx.research.Extractor#save([B)V"
	legacy := want{"legacy", v1, "fx.dep.Paths2", "legacyResolve", "(" + P + "Ljava/lang/String;)" + P, "matched", "not_found", "incomplete", nil}
	if scope == "reachable" {
		legacy.resolution, legacy.search, legacy.model = "missing", "not_evaluated", ""
	}
	cases := []want{
		// (a) private method behind public API: found from extract and save.
		{"write", lib, "fx.research.Extractor", "writeEntry", "(" + P + "[B)V", "matched", "found", "incomplete", []string{extract, saveSBP}},
		// (b) dead private method: not found, model incomplete (c).
		{"unused", lib, "fx.research.Extractor", "unused", "(" + P + ")V", "matched", "not_found", "incomplete", []string{}},
		// (d) overload: the root is the target.
		{"save-bytes", lib, "fx.research.Extractor", "save", "([B)V", "matched", "found", "incomplete", nil},
		// (e) template method through an abstract call.
		{"wipe", lib, "fx.research.internal.Cleaner", "wipe", "(" + P + ")V", "matched", "found", "incomplete", nil},
		// (f) dependency code in the selected 1.0 copy.
		{"resolve", v1, "fx.dep.Paths2", "resolve", "(" + P + "Ljava/lang/String;)" + P, "matched", "found", "incomplete", nil},
		// (g) selected copy, unused method. A reachable-scope bundle keeps
		// only what the roots and the input's own methods reach, so this
		// dependency method is absent there: missing, not not_found.
		legacy,
		// (h) shadowed 2.0 copy.
		{"safe", v2, "fx.dep.Paths2", "safeResolve", "(" + P + "Ljava/lang/String;)" + P, "shadowed", "not_evaluated", "", nil},
		// (i) absent method.
		{"missing", lib, "fx.research.Extractor", "absent", "()V", "missing", "not_evaluated", "", nil},
	}
	var targets []any
	for _, c := range cases {
		targets = append(targets, map[string]any{"id": c.id, "selector": map[string]any{
			"instance_id": c.inst, "class": c.class, "name": c.name, "descriptor": c.desc}})
	}
	reqRaw := request(t, map[string]any{"schema_version": QuerySchema, "analysis_id": b.AnalysisID, "request_id": "control-reach",
		"operation": "reachability", "targets": targets, "roots": map[string]any{"selection": "indexed"}})
	res, err := cli.Query(ctx, reqRaw)
	if err != nil {
		t.Fatalf("reachability: %v\n%s", err, res.Stderr)
	}
	if res.Outcome != OutcomeResult || res.Provenance != ProvenanceAnalysis || res.Response.Provenance.Kind != ProvenanceAnalysis {
		t.Fatalf("outcome %s provenance %s", res.Outcome, res.Provenance)
	}
	savedReq, _ := os.ReadFile(filepath.Join(res.Dir, "request.json"))
	savedResp, _ := os.ReadFile(filepath.Join(res.Dir, "response.json"))
	if !bytes.Equal(savedReq, reqRaw) || !bytes.Equal(savedResp, res.RawResponse) || len(savedResp) == 0 {
		t.Fatal("saved evidence differs from what was exchanged")
	}
	methods := evidenceMethods(t, res.RawResponse)
	for i, c := range cases {
		r := res.Response.Results[i]
		if r.Resolution != c.resolution || r.Search.State != c.search {
			t.Errorf("%s: %s/%s, want %s/%s", c.id, r.Resolution, r.Search.State, c.resolution, c.search)
		}
		if c.model != "" && r.Model.State != c.model {
			t.Errorf("%s: model %s, want %s", c.id, r.Model.State, c.model)
		}
		if c.entries != nil {
			roots := []string{}
			for _, e := range r.Entries {
				roots = append(roots, methods[e.RootNodeID])
				if len(e.Character) != 1 || e.Character[0] != "jvm_rule" {
					t.Errorf("%s: entry character %v", c.id, e.Character)
				}
			}
			sort.Strings(roots)
			if fmt.Sprint(roots) != fmt.Sprint(c.entries) {
				t.Errorf("%s: entries %v, want %v", c.id, roots, c.entries)
			}
		}
	}
	// (d): a zero-edge path, the root is the target.
	if r := res.Response.Results[2]; len(r.Entries) == 0 || methods[r.Entries[0].RootNodeID] != saveB || len(r.Entries[0].Path.EdgeIDs) != 0 {
		t.Errorf("save-bytes entries %+v", r.Entries)
	}
	// (e): three entries, none client dispatch.
	if r := res.Response.Results[3]; r.TotalEntryCount == nil || *r.TotalEntryCount != 3 {
		t.Errorf("wipe: %v entries", r.TotalEntryCount)
	} else {
		for _, e := range r.Entries {
			if e.ClientDispatch {
				t.Errorf("wipe entry marked client dispatch")
			}
		}
	}
	// (f): found from extract.
	if r := res.Response.Results[4]; !hasRoot(r, methods, extract) {
		t.Errorf("resolve not reached from extract")
	}

	// Discovery: JDK Files operations, bodies outside the input.
	callsRaw := request(t, map[string]any{"schema_version": QuerySchema, "analysis_id": b.AnalysisID, "request_id": "control-calls",
		"operation": "calls", "filters": map[string]any{"declared_class_prefix": "java.nio.file.Files"}})
	cres, err := cli.Query(ctx, callsRaw)
	if err != nil {
		t.Fatalf("calls: %v", err)
	}
	var calls struct {
		Records []struct {
			DeclaredName string `json:"declared_name"`
			BodyInInput  bool   `json:"body_in_input"`
		} `json:"records"`
	}
	json.Unmarshal(cres.RawResponse, &calls)
	names := map[string]bool{}
	for _, c := range calls.Records {
		names[c.DeclaredName] = true
		if c.BodyInInput {
			t.Errorf("JDK call %s with a body in the input", c.DeclaredName)
		}
	}
	for _, n := range []string{"write", "delete", "deleteIfExists"} {
		if !names[n] {
			t.Errorf("Files.%s not among calls %v", n, names)
		}
	}

	// Exit 2: invalid requests, recorded as such.
	for name, body := range map[string]map[string]any{
		"unsupported-filter": {"schema_version": QuerySchema, "analysis_id": b.AnalysisID, "request_id": "control-bad-filter",
			"operation": "entries", "filters": map[string]any{"reachable_only": true}},
		"analysis-mismatch": {"schema_version": QuerySchema, "analysis_id": "sha256:" + strings.Repeat("0", 64), "request_id": "control-mismatch",
			"operation": "entries"},
	} {
		r, err := cli.Query(ctx, request(t, body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Exit != 2 || r.Outcome != OutcomeInvalidRequest {
			t.Errorf("%s: exit %d outcome %s", name, r.Exit, r.Outcome)
		}
	}

	// A batch above the contract limit is refused before Ariadne runs.
	many := make([]any, MaxTargets+1)
	for i := range many {
		many[i] = map[string]any{"id": fmt.Sprintf("t%d", i), "method_id": "m-x"}
	}
	if _, err := cli.Query(ctx, request(t, map[string]any{"request_id": "too-many", "targets": many})); err == nil {
		t.Error("257 targets sent")
	}

	// Exit 1: a corrupted bundle copy.
	bad := filepath.Join(work, "bad-bundle")
	copyDir(t, b.Dir, bad)
	nodes := filepath.Join(bad, "nodes.jsonl")
	raw, _ := os.ReadFile(nodes)
	os.WriteFile(nodes, append(raw, '\n', '{', '}', '\n'), 0o644)
	badCLI := &CLI{Binary: bin, Bundle: bad, Evidence: evidence}
	r, err := badCLI.Query(ctx, request(t, map[string]any{"schema_version": QuerySchema, "analysis_id": b.AnalysisID,
		"request_id": "control-corrupt", "operation": "entries"}))
	if err != nil {
		t.Fatalf("corrupt bundle: %v", err)
	}
	if r.Exit != 1 || r.Outcome != OutcomeFailure || r.Response.Error.Code != "BUNDLE_CORRUPT" {
		t.Errorf("corrupt bundle: exit %d outcome %s %+v", r.Exit, r.Outcome, r.Response.Error)
	}

	// Every attempt left its own evidence directory.
	dirs, _ := os.ReadDir(evidence.Root)
	if len(dirs) != 5 {
		t.Errorf("%d evidence directories", len(dirs))
	}
}

func hasRoot(r TargetResult, methods map[string]string, key string) bool {
	for _, e := range r.Entries {
		if methods[e.RootNodeID] == key {
			return true
		}
	}
	return false
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
