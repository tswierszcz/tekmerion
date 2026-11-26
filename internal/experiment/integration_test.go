package experiment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/sandbox"
	"github.com/tswierszcz/tekmerion/internal/state"
)

// writeEntryModel is a local synthetic provider. It proposes one hypothesis on
// Extractor#writeEntry so the experiment has a real Hunt candidate to test.
type writeEntryModel struct{ calls int }

func (p *writeEntryModel) Complete(_ context.Context, r llm.Request) (*llm.Result, error) {
	p.calls++
	var c hunt.Context
	if err := json.Unmarshal([]byte(r.Messages[1].Content), &c); err != nil {
		return nil, err
	}
	o := hunt.Output{Schema: hunt.ResultSchema, InputIdentity: c.Identity, Conclusion: "deferred", Reason: "Synthetic test fixture; no semantic review", Checks: []hunt.Check{}, Candidates: []hunt.Candidate{}, Gaps: c.Gaps}
	for _, m := range c.Methods {
		if c.Entry.Method.Class == "fx.research.Extractor" && c.Entry.Method.Name == "extract" && m.Method.Name == "writeEntry" {
			fact := recon.Fact{Text: "source-derived test hypothesis; authority unestablished", Origin: "model_inferred", Citations: []recon.Citation{m.Source}}
			o.Conclusion = "candidates"
			o.Candidates = append(o.Candidates, hunt.Candidate{LocalID: "write", EntryID: c.Entry.ID, TargetID: m.ID, MechanismKey: "missing-containment", RootCause: m.Source, Anchor: "Files.write(target, body)",
				Principal: fact, Resource: fact, ControlledInput: fact, Conditions: []recon.Fact{fact}, Invariant: "Extraction stays inside the target directory", Mechanism: "Entry name is resolved against the directory without containment",
				Prediction: "A name with a parent component creates a file outside the directory", Experiment: "Extract a normal and a ../ name into a disposable directory",
				Controls: "None observed in the bounded context", Counterarguments: "The caller may intend to grant this authority"})
		}
	}
	raw, _ := json.Marshal(o)
	zero := state.Money(0)
	tokens := int64(100)
	return &llm.Result{HTTPStatus: 200, RawResponse: raw, ID: fmt.Sprintf("local-%d", p.calls), Model: r.Model, Provider: r.Provider, Content: string(raw), Cost: &zero, Tokens: &tokens}, nil
}

func huntWithCandidate(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	src := os.Getenv("ARIADNE_SRC")
	if src == "" {
		t.Skip("ARIADNE_SRC not set: real Ariadne integration skipped")
	}
	if err := sandbox.Available(); err != nil {
		t.Skip(err)
	}
	bin := os.Getenv("ARIADNE_BIN")
	if bin == "" {
		bin = filepath.Join(src, "bin/ariadne")
	}
	ctx := context.Background()
	project, raw, err := manifest.LoadProject("../../testdata/control/project.json")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	work := filepath.Join(root, "prepared")
	if _, err := prepare.Prepare(ctx, prepare.Options{Project: project, ProjectRaw: raw, Checkout: src, Work: work, Ariadne: bin}); err != nil {
		t.Fatal(err)
	}
	reconDir := filepath.Join(root, "recon")
	q := &ariadne.CLI{Binary: bin, Bundle: filepath.Join(work, "bundle"), Evidence: ariadne.Recorder{Root: filepath.Join(reconDir, "ariadne-invocations")}}
	limits := recon.DefaultLimits()
	limits.MaxEntries, limits.MaxBytes = 64, 128<<10
	if err := recon.Start(ctx, recon.Options{Work: work, State: reconDir, Limits: limits, Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	if err := recon.Resume(ctx, reconDir, nil); err != nil {
		t.Fatal(err)
	}
	prices, _ := os.ReadFile("../../testdata/pricing/snapshot.json")
	var p map[string]any
	json.Unmarshal(prices, &p)
	p["retrieved_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	p["valid_until"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	prices, _ = json.Marshal(p)
	budget := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: 20_000_000_000, MaxRequests: 100, MaxTokens: 100_000_000, WallTimeSeconds: 300}
	config := &hunt.Config{Schema: "tekmerion-hunt-model-1", Model: "example/model", Provider: "example-provider", InputTokenBound: 131072, MaxOutputTokens: 8192, MaxAttempts: 2, TimeoutSeconds: 10, AllowSourceContext: true}
	huntDir := filepath.Join(root, "hunt")
	if err := hunt.Start(ctx, hunt.Options{Recon: reconDir, Work: work, State: huntDir, Binary: bin, MaxUnits: 64, Model: config, Prices: prices, Budget: &budget}); err != nil {
		t.Fatal(err)
	}
	if err := hunt.Resume(ctx, huntDir, &writeEntryModel{}, nil); err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(ctx, huntDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snap.Candidates {
		if strings.Contains(c.Canonical, "writeEntry") {
			return ctx, work, huntDir, c.ID
		}
	}
	t.Fatalf("Hunt produced no writeEntry candidate: %+v", snap.Candidates)
	return ctx, "", "", ""
}

func TestRealExperimentReproducesControlCandidate(t *testing.T) {
	ctx, work, huntDir, candidate := huntWithCandidate(t)
	spec := "../../testdata/experiments/extractor/experiment.json"
	dir := filepath.Join(t.TempDir(), "experiment")
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: "sha256:unknown", State: dir}); err == nil {
		t.Fatal("unknown candidate accepted")
	}
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: candidate, State: dir}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, dir); err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, _, _, err := load(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Reproductions) != 1 || snap.Reproductions[0].Outcome != "reproduced" || snap.Reproductions[0].CandidateID != candidate {
		if sha, ok := completed(snap, "capabilities"); ok {
			var c sandbox.Capabilities
			decode(ctx, s, sha, &c)
			for _, v := range c.Checks {
				if !v.OK {
					t.Logf("capability check failed: %+v", v)
				}
			}
			if c.Probe != nil {
				t.Logf("probe stdout %s stderr %s", c.Probe.Stdout, c.Probe.Stderr)
			}
		}
		t.Fatalf("unexpected run: %s %+v", snap.Run.Status, snap.Reproductions)
	}
	obs := map[string]Observation{}
	for _, task := range []string{"case-normal", "case-traversal", "case-corrected-traversal"} {
		sha, _ := completed(snap, task)
		var o Observation
		if err := decode(ctx, s, sha, &o); err != nil {
			t.Fatal(err)
		}
		obs[task] = o
	}
	if o := obs["case-traversal"]; o.Outcome != "property_violated" || strings.Join(o.Escapes, ",") != "/case/escaped.txt" || o.Harness == nil || o.Harness.Exception != "" {
		t.Fatalf("traversal case: %+v", o)
	}
	if o := obs["case-normal"]; o.Outcome != "property_held" || len(o.Escapes) != 0 || len(o.Listing.Entries) != 2 || o.Listing.Entries[1].Path != "jail/entry.txt" || !o.Listing.Entries[1].Promoted {
		t.Fatalf("normal case: %+v", o)
	}
	if o := obs["case-corrected-traversal"]; o.Outcome != "target_exception" || o.Assertion != "held" || len(o.Escapes) != 0 || o.Harness == nil || !strings.Contains(o.Harness.Exception, "entry outside the target directory") {
		t.Fatalf("corrected control case: %+v", o)
	}
	var rec VariantRecord
	sha, _ := completed(snap, "correction")
	if err := decode(ctx, s, sha, &rec); err != nil || rec.Variant == nil || len(rec.Variant.Changed) != 1 || rec.Sources["testdata/research/lib/fx/research/Extractor.java"] != rec.Variant.Changed[0].After {
		t.Fatalf("variant record: %+v %v", rec, err)
	}
	report, err := Report(ctx, s, snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Established: **true**", "Reproduction: **reproduced**", "Defect: **candidate**", "## Corrected variant", "operator-supplied patch", "| traversal | candidate | original | **property_violated** |", "| corrected-traversal | control | corrected | **target_exception** |"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	again, err := Report(ctx, s, snap)
	if err != nil || again != report {
		t.Fatal("report regeneration is not deterministic")
	}
	s.Close()
	if err := Resume(ctx, dir); err != nil {
		t.Fatal("resume of a completed run must be a no-op: ", err)
	}

	// A patch that does not apply is recorded; the control cannot hold, so
	// the assessment is inconclusive rather than reproduced.
	bad := t.TempDir()
	raw, _ := os.ReadFile(spec)
	var sp map[string]any
	json.Unmarshal(raw, &sp)
	sp["harness"], _ = filepath.Abs("../../testdata/experiments/extractor/ExtractHarness.java")
	sp["correction"] = map[string]any{"patch": "bad.patch", "description": "does not apply"}
	raw, _ = json.Marshal(sp)
	os.WriteFile(filepath.Join(bad, "spec.json"), raw, 0600)
	os.WriteFile(filepath.Join(bad, "bad.patch"), []byte("--- a/missing.java\n+++ b/missing.java\n@@ -1 +1 @@\n-x\n+y\n"), 0600)
	dir3 := filepath.Join(bad, "run")
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: filepath.Join(bad, "spec.json"), Candidate: candidate, State: dir3}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, dir3); err != nil {
		t.Fatal(err)
	}
	s3, err := state.Open(ctx, dir3)
	if err != nil {
		t.Fatal(err)
	}
	snap3, err := s3.Snapshot(ctx)
	s3.Close()
	if err != nil || len(snap3.Reproductions) != 1 || snap3.Reproductions[0].Outcome != "inconclusive" || !strings.Contains(snap3.Reproductions[0].Reason, "corrected-traversal=variant_unavailable") {
		t.Fatalf("unappliable patch: %+v %v", snap3.Reproductions, err)
	}

	// A modified target invalidates reproduction instead of producing evidence.
	dir2 := filepath.Join(t.TempDir(), "tampered")
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: candidate, State: dir2}); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(work, "out", "lib.jar")
	os.Chmod(filepath.Dir(jar), 0700)
	os.Chmod(jar, 0600)
	f, err := os.OpenFile(jar, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("tamper"))
	f.Close()
	if err := Resume(ctx, dir2); err != nil {
		t.Fatal(err)
	}
	s2, err := state.Open(ctx, dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	snap2, err := s2.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap2.Reproductions) != 1 || snap2.Reproductions[0].Outcome != "inconclusive" || !strings.Contains(snap2.Reproductions[0].Reason, "prepared target did not match") {
		t.Fatalf("tampered target: %+v", snap2.Reproductions)
	}
}
