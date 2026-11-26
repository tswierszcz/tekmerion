// Package testsupport builds real control-library runs for integration
// tests. It is imported only by tests; its model is a local synthetic
// provider and makes no network requests.
package testsupport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/recon"
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

// HuntWithCandidate prepares the Ariadne control library, runs offline Recon
// and a Hunt with the local provider, and returns the writeEntry candidate.
// It skips when ARIADNE_SRC is unset.
func HuntWithCandidate(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	src := os.Getenv("ARIADNE_SRC")
	if src == "" {
		t.Skip("ARIADNE_SRC not set: real Ariadne integration skipped")
	}
	bin := os.Getenv("ARIADNE_BIN")
	if bin == "" {
		bin = filepath.Join(src, "bin/ariadne")
	}
	ctx := context.Background()
	project, raw, err := manifest.LoadProject(filepath.Join(Root(), "testdata/control/project.json"))
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
	prices := Prices(t)
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

// Root is the repository root, independent of the test's package directory.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// Prices returns the synthetic pricing snapshot with validity around now.
func Prices(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(Root(), "testdata/pricing/snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p["retrieved_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	p["valid_until"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	raw, _ = json.Marshal(p)
	return raw
}
