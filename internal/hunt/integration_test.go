package hunt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type localModel struct {
	calls    int
	outputs  map[string]json.RawMessage
	badFirst bool
}

func (p *localModel) Complete(_ context.Context, r llm.Request) (*llm.Result, error) {
	p.calls++
	var c Context
	if err := json.Unmarshal([]byte(r.Messages[1].Content), &c); err != nil {
		return nil, err
	}
	o := Output{Schema: ResultSchema, InputIdentity: c.Identity, Conclusion: "no_candidate", Reason: "Synthetic test review of supplied source; no security conclusion", Checks: []Check{{Invariant: "File confinement", Method: "source-review", Observation: "Synthetic source-review fixture; authority and runtime remain unexamined", Citations: []recon.Citation{*c.Entry.Source}}}, Candidates: []Candidate{}, Gaps: c.Gaps}
	if c.Entry.Method.Class == "fx.research.Extractor" {
		for _, m := range c.Methods {
			if m.Method.Name == "writeEntry" || m.Method.Name == "unused" {
				o.Candidates = append(o.Candidates, candidateFor(c, m, m.Method.Name))
			}
		}
		if len(o.Candidates) > 0 {
			o.Conclusion = "candidates"
		}
	}
	raw, _ := json.Marshal(o)
	if p.outputs == nil {
		p.outputs = map[string]json.RawMessage{}
	}
	p.outputs[c.Unit.ID] = raw
	if p.badFirst && p.calls == 1 {
		raw = []byte(`{"schema_version":"hallucinated"}`)
	}
	zero := state.Money(0)
	tokens := int64(100)
	return &llm.Result{HTTPStatus: 200, RawResponse: raw, ID: fmt.Sprintf("local-test-%d", p.calls), Model: r.Model, Provider: r.Provider, Content: string(raw), Cost: &zero, Tokens: &tokens}, nil
}
func preparedRecon(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	src := os.Getenv("ARIADNE_SRC")
	if src == "" {
		t.Skip("ARIADNE_SRC not set")
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
	parent := filepath.Join(root, "recon")
	q := &ariadne.CLI{Binary: bin, Bundle: filepath.Join(work, "bundle"), Evidence: ariadne.Recorder{Root: filepath.Join(parent, "ariadne-invocations")}}
	limits := recon.DefaultLimits()
	limits.MaxEntries = 64
	limits.MaxBytes = 128 << 10
	if err := recon.Start(ctx, recon.Options{Work: work, State: parent, Limits: limits, Offline: true, Querier: q}); err != nil {
		t.Fatal(err)
	}
	if err := recon.Resume(ctx, parent, nil); err != nil {
		t.Fatal(err)
	}
	return ctx, work, parent, bin
}
func modelOptions(t *testing.T, work, parent, bin, dir string) Options {
	t.Helper()
	prices, err := os.ReadFile("../../testdata/pricing/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic rates remain explicitly synthetic. Only validity is set for the test clock.
	var p map[string]any
	if err := json.Unmarshal(prices, &p); err != nil {
		t.Fatal(err)
	}
	p["retrieved_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	p["valid_until"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	prices, _ = json.Marshal(p)
	budget := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: 20_000_000_000, MaxRequests: 100, MaxTokens: 100_000_000, WallTimeSeconds: 300}
	config := &Config{Schema: "tekmerion-hunt-model-1", Model: "example/model", Provider: "example-provider", InputTokenBound: 131072, MaxOutputTokens: 8192, MaxAttempts: 2, TimeoutSeconds: 10, AllowSourceContext: true}
	return Options{Recon: parent, Work: work, State: dir, Binary: bin, MaxUnits: 64, Model: config, Prices: prices, Budget: &budget}
}
func openRun(t *testing.T, ctx context.Context, dir string) (*state.Store, *state.Snapshot, Manifest) {
	t.Helper()
	s, err := state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	snap, m, err := load(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	return s, snap, m
}
func TestRealAriadneHuntResumeDedupAndStaticAxes(t *testing.T) {
	ctx, work, parent, bin := preparedRecon(t)
	dir := filepath.Join(t.TempDir(), "hunt")
	o := modelOptions(t, work, parent, bin, dir)
	if err := Start(ctx, o); err != nil {
		t.Fatal(err)
	}
	s, snap, m := openRun(t, ctx, dir)
	if len(m.Jobs) < 2 {
		t.Fatal("need multiple control API units")
	}
	// Finish one model task before an interruption; Resume must reuse its saved result.
	model := &localModel{badFirst: true}
	var c Context
	if err := decode(ctx, s, m.Jobs[0].ContextSHA, &c); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Execute(ctx, s, m.Jobs[0].TaskID, model, func(content string) error { _, err := ParseOutput([]byte(content), c); return err }); err != nil {
		t.Fatal(err)
	}
	if model.calls != 2 {
		t.Fatal("corrective retry was not bounded/accounted")
	}
	if err := Resume(ctx, dir, model, nil); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Candidates) != 2 || len(snap.Occurrences) < 4 || snap.Budget.Requests != int64(len(m.Jobs)+1) || snap.Budget.Settled != 0 {
		t.Fatalf("unexpected candidates/costs: candidates=%d paths=%d budget=%+v", len(snap.Candidates), len(snap.Occurrences), snap.Budget)
	}
	found, notFound := false, false
	for _, row := range snap.Occurrences {
		var occurrence Occurrence
		if err := decode(ctx, s, row.PayloadSHA, &occurrence); err != nil {
			t.Fatal(err)
		}
		if occurrence.Defect != "candidate" || occurrence.Reproduction != "not_run" || occurrence.Novelty != "undetermined" {
			t.Fatal("static triage promoted a finding")
		}
		a := occurrence.Static
		if a.Execution != "completed" || a.Provenance != "analysis" || a.ValidationScope != "bundle" || a.AttemptSHA == "" {
			t.Fatalf("no accepted real graph evidence: %+v", a)
		}
		var result ariadne.TargetResult
		if err := json.Unmarshal(a.Result, &result); err != nil {
			t.Fatal(err)
		}
		found = found || result.Search.State == "found"
		notFound = notFound || result.Search.State == "not_found"
		raw, err := s.Get(ctx, a.ResponseSHA)
		if err != nil {
			t.Fatal(err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(compact.String(), string(a.Result)) {
			t.Fatal("per-target static record was rewritten")
		}
	}
	if !found || !notFound {
		t.Fatalf("lost independent positive/negative static results found=%v not_found=%v", found, notFound)
	}
	calls := model.calls
	before, _ := json.Marshal(snap)
	if err := Resume(ctx, dir, nil, nil); err != nil {
		t.Fatal(err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(after)
	if calls != model.calls || string(raw) != string(before) {
		t.Fatal("completed resume changed evidence/costs")
	}
	report, err := Report(ctx, s, snap)
	if err != nil || !strings.Contains(report, "not_run") || !strings.Contains(report, "Counterarguments") {
		t.Fatalf("report missing independent axes: %v", err)
	}
	// Replay against the same immutable input requires no provider and preserves exact identity.
	replay, _ := json.Marshal(Replay{Schema: "tekmerion-hunt-replay-1", Outputs: model.outputs})
	replayDir := filepath.Join(t.TempDir(), "replay")
	if err := Start(ctx, Options{Recon: parent, Work: work, State: replayDir, Binary: bin, MaxUnits: 64, Replay: replay}); err != nil {
		t.Fatal(err)
	}
	// A rejected adapter attempt preserves raw evidence without contributing graph axes.
	invalidDir := filepath.Join(t.TempDir(), "invalid-static")
	if err := Start(ctx, Options{Recon: parent, Work: work, State: invalidDir, Binary: bin, MaxUnits: 64, Replay: replay}); err != nil {
		t.Fatal(err)
	}
	invalid := rejectProof{inner: &ariadne.CLI{Binary: bin, Bundle: filepath.Join(work, "bundle"), Evidence: ariadne.Recorder{Root: filepath.Join(invalidDir, "ariadne-invocations")}}}
	if err := Resume(ctx, invalidDir, nil, invalid); err != nil {
		t.Fatal(err)
	}
	is, isnap, _ := openRun(t, ctx, invalidDir)
	for _, row := range isnap.Occurrences {
		var occurrence Occurrence
		if err := decode(ctx, is, row.PayloadSHA, &occurrence); err != nil {
			t.Fatal(err)
		}
		if occurrence.Static.Execution != "unavailable" || len(occurrence.Static.Result) != 0 || occurrence.Static.ResponseSHA == "" || occurrence.Static.Diagnostic == "" {
			t.Fatal("rejected proof contributed accepted static axes or lost raw evidence")
		}
	}
	// A vanished preparation is a precise static blocker; source-grounded candidates survive.
	moved := work + "-moved"
	if err := os.Rename(work, moved); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(moved, work)
	if err := Resume(ctx, replayDir, nil, nil); err != nil {
		t.Fatal(err)
	}
	rs, rsnap, _ := openRun(t, ctx, replayDir)
	if len(rsnap.Candidates) != 2 || rsnap.Budget != nil {
		t.Fatal("replay lost candidates or invented spend")
	}
	for _, row := range rsnap.Occurrences {
		var occurrence Occurrence
		if err := decode(ctx, rs, row.PayloadSHA, &occurrence); err != nil {
			t.Fatal(err)
		}
		if occurrence.Static.Execution != "unavailable" || len(occurrence.Static.Result) != 0 || occurrence.Static.Diagnostic == "" {
			t.Fatal("missing bundle became a graph claim")
		}
	}
	if err := rs.Verify(ctx, rsnap); err != nil {
		t.Fatal(err)
	}
}
func TestHuntOfflineAndPartialBudget(t *testing.T) {
	ctx, work, parent, bin := preparedRecon(t)
	root := t.TempDir()
	offline := filepath.Join(root, "offline")
	if err := Start(ctx, Options{Recon: parent, Work: work, State: offline, Binary: bin, MaxUnits: 1, Offline: true}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, offline, nil, nil); err != nil {
		t.Fatal(err)
	}
	_, snap, m := openRun(t, ctx, offline)
	if len(snap.Candidates) != 0 || len(snap.CoverageHistory) != 1 || snap.CoverageHistory[0].Status != "deferred" || snap.Budget != nil || len(m.DeferredUnits) == 0 {
		t.Fatal("offline falsely checked units or hid unselected work")
	}
	limited := filepath.Join(root, "limited")
	o := modelOptions(t, work, parent, bin, limited)
	o.Budget.MaxRequests = 1
	if err := Start(ctx, o); err != nil {
		t.Fatal(err)
	}
	provider := &localModel{}
	if err := Resume(ctx, limited, provider, nil); !errors.Is(err, state.ErrBudget) {
		t.Fatalf("expected bounded stop: %v", err)
	}
	s, snap, m := openRun(t, ctx, limited)
	if len(snap.CoverageHistory) != 1 || provider.calls != 1 || snap.Budget.Requests != 1 {
		t.Fatalf("completed unit lost on later budget exhaustion: %+v", snap)
	}
	if err := s.Verify(ctx, snap); err != nil {
		t.Fatal(err)
	}
	// Pending units remain visible; resume cannot reset the exhausted budget.
	if err := Resume(ctx, limited, provider, nil); !errors.Is(err, state.ErrBudget) || provider.calls != 1 {
		t.Fatalf("resume bypassed budget: %v calls=%d", err, provider.calls)
	}
	if len(m.Jobs) < 2 {
		t.Fatal("partial-budget test needs queued work")
	}
}

func TestHuntUnitSelection(t *testing.T) {
	ctx, work, parent, bin := preparedRecon(t)
	root := t.TempDir()
	first := filepath.Join(root, "first")
	if err := Start(ctx, Options{Recon: parent, Work: work, State: first, Binary: bin, MaxUnits: 1, Offline: true}); err != nil {
		t.Fatal(err)
	}
	_, _, m := openRun(t, ctx, first)
	if len(m.DeferredUnits) == 0 {
		t.Skip("fixture has a single planned unit")
	}
	planned := len(m.Jobs) + len(m.DeferredUnits)
	target := m.DeferredUnits[len(m.DeferredUnits)-1]
	picked := filepath.Join(root, "picked")
	if err := Start(ctx, Options{Recon: parent, Work: work, State: picked, Binary: bin, MaxUnits: 64, Units: []string{target}, Offline: true}); err != nil {
		t.Fatal(err)
	}
	_, _, m = openRun(t, ctx, picked)
	if len(m.Jobs) != 1 || len(m.DeferredUnits) != planned-1 || len(m.SelectedUnits) != 1 || m.SelectedUnits[0] != target {
		t.Fatalf("selection did not pick exactly the requested unit: jobs=%d deferred=%d selected=%v", len(m.Jobs), len(m.DeferredUnits), m.SelectedUnits)
	}
	for _, id := range m.DeferredUnits {
		if id == target {
			t.Fatal("selected unit was deferred")
		}
	}
	for name, o := range map[string]Options{
		"unknown":   {Units: []string{"sha256:not-a-unit"}, MaxUnits: 64},
		"duplicate": {Units: []string{target, target}, MaxUnits: 64},
		"over max":  {Units: []string{target, "sha256:other"}, MaxUnits: 1},
	} {
		o.Recon, o.Work, o.State, o.Binary, o.Offline = parent, work, filepath.Join(root, strings.ReplaceAll(name, " ", "-")), bin, true
		if err := Start(ctx, o); err == nil {
			t.Errorf("%s selection was accepted", name)
		}
	}
}

type rejectProof struct{ inner ariadne.Querier }

func (q rejectProof) Query(ctx context.Context, raw []byte) (*ariadne.Result, error) {
	result, err := q.inner.Query(ctx, raw)
	if err != nil {
		return result, err
	}
	result.Outcome = ariadne.OutcomeUnusable
	result.ValidationScope = ""
	return result, fmt.Errorf("test: rejected graph proof")
}
