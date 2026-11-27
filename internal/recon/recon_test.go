package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type discovery struct {
	entries  []sourceindex.Entry
	calls    int
	bad      bool
	paginate bool
}

func (d *discovery) Query(_ context.Context, raw []byte) (*ariadne.Result, error) {
	d.calls++
	var request struct {
		Operation string `json:"operation"`
		Filters   struct {
			Nodes []string `json:"node_ids"`
		} `json:"filters"`
		Cursor *string `json:"cursor"`
	}
	if err := jsonx.Decode(raw, &request, true); err != nil {
		return nil, err
	}
	records := []any{}
	switch request.Operation {
	case "entries":
		for i := range d.entries {
			records = append(records, map[string]any{"record_type": "root", "node_id": fmt.Sprintf("node-%d", i)})
		}
	case "methods":
		if len(request.Filters.Nodes) != len(d.entries) {
			return nil, errors.New("method discovery was not restricted to entry nodes")
		}
		for i, e := range d.entries {
			records = append(records, map[string]any{"node_id": fmt.Sprintf("node-%d", i), "node_kind": "method", "method": map[string]any{"class": e.Class, "name": e.Name, "descriptor": e.Descriptor, "class_sha256": e.ClassSHA256, "instance_id": "app"}})
		}
	}
	var cursor any
	truncated := false
	if d.paginate {
		cursor = "repeat-cursor"
		truncated = true
	}
	response, _ := json.Marshal(map[string]any{"records": records, "page": map[string]any{"next_cursor": cursor, "truncated": truncated, "work_complete": true}})
	result := &ariadne.Result{RawRequest: raw, RawResponse: response, Outcome: ariadne.OutcomeResult, ValidationScope: "bundle", Provenance: ariadne.ProvenanceFixture}
	if d.bad {
		result.Outcome = ariadne.OutcomeUnusable
		return result, errors.New("fixture invalid graph proof")
	}
	return result, nil
}
func fixture(t *testing.T) (string, *discovery) {
	t.Helper()
	work := t.TempDir()
	if err := os.CopyFS(filepath.Join(work, "src/src"), os.DirFS("../../testdata/sourceindex/src")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	jar, err := os.ReadFile("../../testdata/sourceindex/sample.jar")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "out/sample.jar"), jar, 0600); err != nil {
		t.Fatal(err)
	}
	project := manifest.Project{SchemaVersion: manifest.ProjectSchema, Target: manifest.Target{Repository: "https://example.invalid/fixture", Revision: strings.Repeat("a", 40), SourceRoots: []sourceindex.Root{{Path: "src", Artifact: "sample.jar"}}}, Build: manifest.Recipe{Network: manifest.NetworkNone, Steps: []manifest.Step{{Name: "fixture", Argv: []string{"true"}}}, Outputs: manifest.Outputs{App: "sample.jar"}}, Scenario: manifest.Scenario{Roots: "api"}}
	projectRaw, _ := json.Marshal(project)
	ix, err := sourceindex.Build(filepath.Join(work, "src"), filepath.Join(work, "out"), project.Target.SourceRoots)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(work, "source-index.json")
	if err := ix.Save(indexPath); err != nil {
		t.Fatal(err)
	}
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(work, "src/src/ex/pkg/Sample.java"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, "bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	identity, meta := []byte(`{"fixture":"identity"}`), []byte(`{"fixture":"manifest"}`)
	for name, raw := range map[string][]byte{"identity.json": identity, "manifest.json": meta} {
		if err := os.WriteFile(filepath.Join(work, "bundle", name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := manifest.Run{SchemaVersion: manifest.RunSchema, Project: projectRaw, ProjectOriginal: projectRaw, ProjectSHA256: hash(projectRaw), Source: manifest.Source{Repository: project.Target.Repository, Commit: project.Target.Revision, Files: 1, TreeSHA256: hash([]byte(hash(src) + " 100644 src/ex/pkg/Sample.java\n"))}, Build: manifest.Build{Network: manifest.NetworkNone, Steps: []manifest.StepRun{{Name: "fixture", Exit: 0}}}, Artifacts: manifest.Artifacts{App: manifest.File{Path: "sample.jar", SHA256: hash(jar), Size: int64(len(jar))}, Classpath: []string{"sample.jar"}, ClasspathSHA256: hash([]byte(hash(jar) + " sample.jar\n"))}, SourceIndex: manifest.SourceIndex{File: manifest.File{Path: "source-index.json", SHA256: hash(indexRaw), Size: int64(len(indexRaw))}, Methods: len(ix.Entries)}, Analysis: &manifest.Analysis{AnalysisID: hash(identity), Bundle: "bundle", ManifestSHA256: hash(meta), IdentitySHA256: hash(identity), Roots: "api"}}
	for _, e := range ix.Entries {
		if e.Binding == sourceindex.BindingBuildVerified {
			run.SourceIndex.Located++
		}
	}
	if err := run.Save(filepath.Join(work, "run-manifest.json")); err != nil {
		t.Fatal(err)
	}
	selected := []sourceindex.Entry{}
	for _, e := range ix.Entries {
		if e.Class == "ex.pkg.Sample" && (e.Name == "greet" || e.Name == "sum") {
			selected = append(selected, e)
		}
	}
	if len(selected) != 2 {
		t.Fatal("missing sample methods")
	}
	return work, &discovery{entries: selected}
}
func load(t *testing.T, dir string) (*state.Store, *state.Snapshot, Manifest, Context) {
	t.Helper()
	s, err := state.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Get(context.Background(), snap.Run.ManifestSHA)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := jsonx.Decode(raw, &m, false); err != nil {
		t.Fatal(err)
	}
	raw, err = s.Get(context.Background(), m.ContextSHA)
	if err != nil {
		t.Fatal(err)
	}
	var c Context
	if err := jsonx.Decode(raw, &c, false); err != nil {
		t.Fatal(err)
	}
	return s, snap, m, c
}
func TestOfflineReconPreparedSourceToPersistentCoverage(t *testing.T) {
	work, q := fixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	if err := Start(ctx, Options{Work: work, State: dir, Limits: DefaultLimits(), Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, dir, nil); err != nil {
		t.Fatal(err)
	}
	s, snap, _, c := load(t, dir)
	if snap.Run.Status != "completed" || len(snap.Coverage) != 2 || len(snap.Attempts) != 2 || len(c.Entries) != 2 || len(c.Excerpts) != 2 || q.calls != 3 {
		t.Fatalf("unexpected Recon state: %+v", snap)
	}
	for _, unit := range snap.Coverage {
		if unit.Status != "planned" {
			t.Fatal("baseline silently checked source")
		}
	}
	if err := s.Verify(ctx, snap); err != nil {
		t.Fatal(err)
	}
	for _, excerpt := range c.Excerpts {
		raw, err := s.Get(ctx, excerpt.SHA)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		if strings.Join(lines[excerpt.Start-1:excerpt.End], "\n") != excerpt.Text {
			t.Fatal("source excerpt differs from archived file")
		}
	}
	before, _ := json.Marshal(snap)
	if err := Resume(ctx, dir, nil); err != nil {
		t.Fatal(err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repeated, _ := json.Marshal(after)
	if string(before) != string(repeated) {
		t.Fatal("resume changed completed coverage")
	}
}
func TestOutputRejectsHallucinationsAndInflatedCoverage(t *testing.T) {
	work, q := fixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := Start(context.Background(), Options{Work: work, State: dir, Limits: DefaultLimits(), Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	_, _, _, c := load(t, dir)
	c.Declarations = []string{"untrusted caller controls only entry names"}
	c.Identity = contextIdentity(c)
	tests := []struct {
		name   string
		mutate func(*Output)
	}{
		{"stale context", func(o *Output) { o.InputIdentity = hash([]byte("old source")) }},
		{"hallucinated source", func(o *Output) { o.Coverage[0].Citations[0].Path = "../../etc/passwd" }},
		{"wrong source hash", func(o *Output) { o.Coverage[0].Citations[0].SHA = hash([]byte("wrong")) }},
		{"outside excerpt", func(o *Output) { o.Coverage[0].Citations[0].End = 100000 }},
		{"missing method", func(o *Output) { o.Coverage[0].EntryID = "invented" }},
		{"duplicate unit", func(o *Output) { o.Coverage = append(o.Coverage, o.Coverage[0]) }},
		{"dropped surface", func(o *Output) { o.Coverage = o.Coverage[:1] }},
		{"checked without work", func(o *Output) { o.Coverage[0].Status = "checked" }},
		{"invented authority", func(o *Output) { o.Assumptions[0].Text = "caller controls the entire host filesystem" }},
		{"lost declaration", func(o *Output) { o.Assumptions = nil }},
		{"lost static gap", func(o *Output) { o.Gaps = nil }},
		{"experimentally checked claim", func(o *Output) { o.Assumptions[0].Origin = "experimentally_checked" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := Baseline(c)
			test.mutate(&o)
			if err := o.Validate(c); err == nil {
				t.Fatal("ungrounded output accepted")
			}
		})
	}
}
func TestDeferredSourceAndFailedAdapterRemainVisible(t *testing.T) {
	work, q := fixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	limits := DefaultLimits()
	limits.MaxEntries = 1
	if err := Start(context.Background(), Options{Work: work, State: dir, Limits: limits, Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(context.Background(), dir, nil); err != nil {
		t.Fatal(err)
	}
	_, snap, _, c := load(t, dir)
	if c.DeferredCount != 1 || len(snap.Coverage) != 2 {
		t.Fatal("context limit dropped known coverage")
	}
	deferred := 0
	for _, unit := range snap.Coverage {
		if unit.Status == "deferred" {
			deferred++
		}
	}
	if deferred != 1 {
		t.Fatal("deferred surface was marked planned/checked")
	}
	_, q = fixture(t)
	q.bad = true
	badDir := filepath.Join(t.TempDir(), "bad")
	if err := Start(context.Background(), Options{Work: work, State: badDir, Limits: DefaultLimits(), Offline: true, Querier: q}); err == nil {
		t.Fatal("unusable graph evidence accepted")
	}
}
func TestPreparationTamperingFailsBeforeDiscovery(t *testing.T) {
	for _, member := range []string{"src/src/ex/pkg/Sample.java", "out/sample.jar", "source-index.json", "bundle/identity.json"} {
		t.Run(member, func(t *testing.T) {
			work, q := fixture(t)
			if err := os.WriteFile(filepath.Join(work, member), []byte("tampered"), 0600); err != nil {
				t.Fatal(err)
			}
			err := Start(context.Background(), Options{Work: work, State: filepath.Join(t.TempDir(), "state"), Limits: DefaultLimits(), Offline: true, Querier: q})
			if err == nil || q.calls != 0 {
				t.Fatal("corrupted preparation entered analysis")
			}
		})
	}
}
func TestPaginationLoopAndSymlinkRefused(t *testing.T) {
	work, q := fixture(t)
	q.paginate = true
	if err := Start(context.Background(), Options{Work: work, State: filepath.Join(t.TempDir(), "state"), Limits: DefaultLimits(), Offline: true, Querier: q}); err == nil {
		t.Fatal("cursor loop accepted")
	}
	dir := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare.ReadFile(dir, "escape", 4096); err == nil {
		t.Fatal("symlink source member accepted")
	}
	linkedRoot := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(dir, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare.ReadFile(linkedRoot, "escape", 4096); err == nil {
		t.Fatal("symlink read root accepted")
	}
	if _, err := prepare.ReadFile(dir, "../escape", 4096); err == nil {
		t.Fatal("relative escape accepted")
	}
}
func TestResumeCoverageAfterReconWithoutOriginalPreparation(t *testing.T) {
	work, q := fixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	if err := Start(ctx, Options{Work: work, State: dir, Limits: DefaultLimits(), Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	s, snap, _, _ := load(t, dir)
	// Simulate interruption after accepted Recon but before coverage projection.
	var task state.Task
	for _, item := range snap.Tasks {
		if item.ID == "recon" {
			task = item
		}
	}
	claim, err := s.Claim(ctx, snap.Run.ID, "recon", "first-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, *claim, "completed", task.InputSHA, ""); err != nil {
		t.Fatal(err)
	}
	moved := work + "-moved"
	if err := os.Rename(work, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Rename(moved, work) })
	if err := Resume(ctx, dir, nil); err != nil {
		t.Fatal(err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Run.Status != "completed" || len(after.Coverage) != 2 || q.calls != 3 || len(after.Attempts) != 2 {
		t.Fatal("resume repeated discovery/Recon instead of saved projection")
	}
}

type modelReplay struct {
	calls          int
	malformedFirst bool
}

func (p *modelReplay) Complete(_ context.Context, request llm.Request) (*llm.Result, error) {
	p.calls++
	var c Context
	if err := jsonx.Decode([]byte(request.Messages[1].Content), &c, false); err != nil {
		return nil, err
	}
	if request.Role != "recon" || request.PromptRevision != PromptRevision || !request.JSONOutput {
		return nil, errors.New("wrong model protocol")
	}
	output := Baseline(c)
	output.Controls = append(output.Controls, Fact{Text: "Control applicability is still a model inference over this cited entry.", Origin: "model_inferred", Citations: []Citation{c.Excerpts[0].Citation}})
	if p.malformedFirst && p.calls == 1 {
		output.Coverage[0].Citations[0].Path = "invented.java"
	}
	raw, _ := json.Marshal(output)
	zero := state.Money(0)
	tokens := int64(20)
	return &llm.Result{ID: fmt.Sprintf("recon-replay-%d", p.calls), Model: request.Model, Provider: request.Provider, Content: string(raw), Cost: &zero, Tokens: &tokens, RawResponse: raw}, nil
}
func TestModelReconValidatesBeforeCoverageAndRetriesRemainBounded(t *testing.T) {
	work, q := fixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	now := time.Now()
	prices := pricing.Snapshot{Schema: pricing.SnapshotSchema, Source: "synthetic:test", Currency: "USD", RetrievedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), Routes: []pricing.Route{{Model: "recon-fixture", Provider: "local", Input: "0", Output: "0", Request: "0", Complete: true, ReasoningIncluded: true}}}
	priceRaw, _ := json.Marshal(prices)
	config := Config{Schema: "tekmerion-recon-model-1", Model: "recon-fixture", Provider: "local", InputTokenBound: 20000, MaxOutputTokens: 2000, MaxAttempts: 2, TimeoutSeconds: 1, AllowSourceContext: true}
	budget := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: state.Dollar, MaxRequests: 10, MaxTokens: 100000, WallTimeSeconds: 60}
	if err := Start(context.Background(), Options{Work: work, State: dir, Limits: DefaultLimits(), Model: &config, Prices: priceRaw, Budget: &budget, Querier: q}); err != nil {
		t.Fatal(err)
	}
	provider := &modelReplay{malformedFirst: true}
	if err := Resume(context.Background(), dir, provider); err != nil {
		t.Fatal(err)
	}
	s, snap, _, c := load(t, dir)
	if provider.calls != 2 || len(snap.Coverage) != 2 || snap.Budget.Requests != 2 || snap.Budget.Settled != 0 || snap.Run.Status != "completed" {
		t.Fatalf("model path bypassed validation/accounting: %+v", snap)
	}
	for _, attempt := range snap.Attempts {
		if attempt.TaskID == "recon" && attempt.Number == 1 && attempt.Outcome != "interrupted" {
			t.Fatal("hallucinated response accepted")
		}
	}
	text, err := Architecture(context.Background(), s, snap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "model\\_inferred") || !strings.Contains(text, "not checked coverage") {
		t.Fatalf("model authority/coverage was promoted: %s", text)
	}
	before, _ := json.Marshal(snap)
	if err := Resume(context.Background(), dir, nil); err != nil {
		t.Fatal(err)
	}
	after, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(after)
	if string(before) != string(raw) || provider.calls != 2 {
		t.Fatal("completed model Recon reran")
	}
	if c.PromptSHA != hash([]byte(prompt)) || c.CatalogueSHA != hash(catalogue) {
		t.Fatal("prompt/catalogue provenance lost")
	}
}
func TestLegacyProjectGapAndOriginalByteVerification(t *testing.T) {
	work, _ := fixture(t)
	path := filepath.Join(work, "run-manifest.json")
	run, err := manifest.LoadRun(path)
	if err != nil {
		t.Fatal(err)
	}
	// Reformatting the embedded JSON is harmless because original file bytes
	// are separately retained. A change in their semantics is not harmless.
	if _, err := prepare.Verify(work); err != nil {
		t.Fatal(err)
	}
	run.ProjectOriginal = nil
	if err := run.Save(path); err != nil {
		t.Fatal(err)
	}
	verified, err := prepare.Verify(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Gaps) != 1 {
		t.Fatal("legacy original-byte limitation hidden")
	}
	run.ProjectOriginal = []byte(`{}`)
	if err := run.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare.Verify(work); err == nil {
		t.Fatal("wrong original project hash accepted")
	}
}

func TestDocumentAndTestContextIsBoundedAndArchived(t *testing.T) {
	work, _ := fixture(t)
	verified, err := prepare.Verify(work)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		path := filepath.Join(work, "src", fmt.Sprintf("README-%d.md", i))
		if err := os.WriteFile(path, []byte("Declared usage and caller authority.\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := state.Create(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := Context{Excerpts: []Excerpt{}, Gaps: []string{}}
	if err := addDocuments(context.Background(), s, verified, &c, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if len(c.Excerpts) != 4 || len(c.Gaps) != 1 {
		t.Fatal("documentation cap or deferred count lost")
	}
	for _, excerpt := range c.Excerpts {
		if excerpt.Kind != "documentation" {
			t.Fatal("document source kind lost")
		}
		if _, err := s.Get(context.Background(), excerpt.SHA); err != nil {
			t.Fatal("document full-file evidence not saved")
		}
	}
	// The outer preparation check rejects adding these documents to an already
	// prepared immutable source tree; context collection cannot silently rebind.
	if _, err := prepare.Verify(work); err == nil {
		t.Fatal("source additions after preparation accepted")
	}
}

func TestCoverageCanonicalIdentityKeepsSourceRevisionSeparate(t *testing.T) {
	c := Context{Repository: "https://example.invalid/repo", ScenarioSHA: hash([]byte("api scenario")), SourceSHA: hash([]byte("original source"))}
	entry := Entry{Method: sourceindex.Method{Class: "example.API", Name: "write", Descriptor: "(Ljava/lang/String;)V", ClassSHA256: hash([]byte("original class"))}, Subsystem: "example"}
	first, refs := canonicalUnit(c, entry)
	c.SourceSHA = hash([]byte("changed source"))
	entry.Method.ClassSHA256 = hash([]byte("changed class"))
	entry.SelectionReason = "different human display bookkeeping"
	second, again := canonicalUnit(c, entry)
	if first != second || refs != again {
		t.Fatal("coverage identity depends on source hashes or display data")
	}
	entry.Method.Descriptor = "([B)V"
	overload, _ := canonicalUnit(c, entry)
	if overload == first {
		t.Fatal("overloaded API canonical identity collision")
	}
	c.ScenarioSHA = hash([]byte("another scenario"))
	other, _ := canonicalUnit(c, entry)
	if other == overload {
		t.Fatal("scenarios collapsed into one unit")
	}
}
func TestThreatModelDeclarationsAreQuotable(t *testing.T) {
	obj := `{"principal": "An application calls the API.", "authority": "The caller chooses the output directory."}`
	for raw, want := range map[string][]string{
		`"Callers are trusted."`:      {"Callers are trusted."},
		`["first", "second"]`:         {"first", "second"},
		obj:                           {"An application calls the API.", "The caller chooses the output directory."},
		`{"a": "x", "b": {"c": "y"}}`: {`{"a": "x", "b": {"c": "y"}}`},
		`{"a": ""}`:                   {`{"a": ""}`},
		`["x", 1]`:                    {`["x", 1]`},
		`{}`:                          {`{}`},
	} {
		if got := declarations(json.RawMessage(raw)); !slices.Equal(got, want) {
			t.Errorf("declarations(%s) = %q, want %q", raw, got, want)
		}
	}
}
