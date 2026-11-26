package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/sandbox"
	"github.com/tswierszcz/tekmerion/internal/state"
	"github.com/tswierszcz/tekmerion/internal/testsupport"
)

// supportingModel is a local synthetic verifier: it supports every claim by
// citing the root cause and the recorded experiment cases.
type supportingModel struct{ calls int }

func (p *supportingModel) Complete(_ context.Context, r llm.Request) (*llm.Result, error) {
	p.calls++
	var c Context
	if err := json.Unmarshal([]byte(r.Messages[1].Content), &c); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(verdict(c, "supported"))
	zero := state.Money(0)
	tokens := int64(100)
	return &llm.Result{HTTPStatus: 200, RawResponse: raw, ID: fmt.Sprintf("local-validate-%d", p.calls), Model: r.Model, Provider: r.Provider, Content: string(raw), Cost: &zero, Tokens: &tokens}, nil
}

func verdict(c Context, decision string) Output {
	o := Output{Schema: ResultSchema, InputIdentity: c.Identity, Decision: decision, Reason: "Synthetic test verdict; not a security review", Controls: []Control{}, Unresolved: []string{}, Gaps: c.Gaps}
	for _, cl := range c.Claims {
		a := Assessment{Claim: cl.ID, Status: "supported", Observation: "synthetic observation", Citations: []recon.Citation{c.RootCause}, Evidence: []string{"traversal", "corrected-traversal"}}
		if decision == "refuted" && strings.HasSuffix(cl.ID, ".principal") {
			a.Status, a.Observation = "refuted", "synthetic: the API is documented as granting the caller filesystem authority"
		}
		o.Claims = append(o.Claims, a)
	}
	return o
}

func experimented(t *testing.T) (context.Context, string) {
	t.Helper()
	if err := sandbox.Available(); err != nil {
		t.Skip(err)
	}
	ctx, work, huntDir, candidate := testsupport.HuntWithCandidate(t)
	dir := filepath.Join(t.TempDir(), "experiment")
	spec := filepath.Join(testsupport.Root(), "testdata/experiments/extractor/experiment.json")
	if err := experiment.Start(ctx, experiment.Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: candidate, State: dir}); err != nil {
		t.Fatal(err)
	}
	if err := experiment.Resume(ctx, dir); err != nil {
		t.Fatal(err)
	}
	return ctx, dir
}

func decided(t *testing.T, ctx context.Context, dir string) (*state.Store, *state.Snapshot, Decision) {
	t.Helper()
	s, err := state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Decisions) != 1 {
		t.Fatalf("run %s decisions %+v", snap.Run.Status, snap.Decisions)
	}
	var d Decision
	if err := decode(ctx, s, snap.Decisions[0].PayloadSHA, &d); err != nil {
		t.Fatal(err)
	}
	return s, snap, d
}

func TestRealValidationLabels(t *testing.T) {
	ctx, exp := experimented(t)
	c, _, err := BuildContext(ctx, exp)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := BuildContext(ctx, exp)
	if err != nil || again.Identity != c.Identity {
		t.Fatal("verifier context is not deterministic")
	}
	if c.Experiment.Reproduction != "reproduced" || len(c.Experiment.Cases) != 3 || c.Experiment.Patch == "" || len(c.Claims) < 6 || !strings.Contains(c.Experiment.Harness, "ExtractHarness") {
		t.Fatalf("context: %+v", c.Experiment)
	}
	root := t.TempDir()

	// Model mode through the gateway with a local provider: supported claims,
	// a reproduced experiment and a reproduced fresh replay confirm.
	budget := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: 20_000_000_000, MaxRequests: 10, MaxTokens: 10_000_000, WallTimeSeconds: 600}
	prices := testsupport.Prices(t)
	cfg := &Config{Schema: "tekmerion-validate-model-1", Model: "example/model", Provider: "example-provider", InputTokenBound: 131072, MaxOutputTokens: 8192, MaxAttempts: 2, TimeoutSeconds: 10, AllowSourceContext: true}
	confirmed := filepath.Join(root, "confirmed")
	if err := Start(ctx, Options{Experiment: exp, State: confirmed, Model: cfg, Prices: prices, Budget: &budget}); err != nil {
		t.Fatal(err)
	}
	model := &supportingModel{}
	if err := Resume(ctx, confirmed, model); err != nil {
		t.Fatal(err)
	}
	s, snap, d := decided(t, ctx, confirmed)
	if d.Label != "confirmed" || d.Replay != "reproduced" || d.Defect != "confirmed" || d.Novelty != "undetermined" || model.calls != 1 || snap.Budget == nil || snap.Budget.Requests != 1 {
		t.Fatalf("model validation: %+v calls=%d", d, model.calls)
	}
	report, err := Report(ctx, s, snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Label: **confirmed**", "Replay: **reproduced**", "Decision: **supported**", "does not establish novelty"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if err := Resume(ctx, confirmed, nil); err != nil || model.calls != 1 {
		t.Fatal("completed validation must not call the model again")
	}

	// A recorded refutation rejects despite the reproduced effect.
	raw, _ := json.Marshal(verdict(c, "refuted"))
	rejected := filepath.Join(root, "rejected")
	if err := Start(ctx, Options{Experiment: exp, State: rejected, Replay: raw}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, rejected, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, d := decided(t, ctx, rejected); d.Label != "rejected" || len(d.Refuted) == 0 || !strings.Contains(d.Reason, "does not restore") {
		t.Fatalf("refuted validation: %+v", d)
	}

	// Offline review leaves the exact unresolved fact.
	offline := filepath.Join(root, "offline")
	if err := Start(ctx, Options{Experiment: exp, State: offline, Offline: true}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, offline, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, d := decided(t, ctx, offline); d.Label != "needs_validation" || !strings.Contains(strings.Join(d.Unresolved, ";"), "independent verification was not performed") {
		t.Fatalf("offline validation: %+v", d)
	}

	// A stale replay (wrong identity) is refused before any run is created.
	stale := verdict(c, "supported")
	stale.InputIdentity = "sha256:stale"
	raw, _ = json.Marshal(stale)
	if err := Start(ctx, Options{Experiment: exp, State: filepath.Join(root, "stale"), Replay: raw}); err == nil {
		t.Fatal("stale verifier output accepted")
	}
}
