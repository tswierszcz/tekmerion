package validate

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type Config recon.Config

type Manifest struct {
	Schema          string `json:"schema_version"`
	Mode            string `json:"mode"`
	ParentSHA       string `json:"parent_snapshot_sha256"`
	ParentRunID     string `json:"parent_run_id"`
	Experiment      string `json:"experiment_state"`
	CandidateID     string `json:"candidate_id"`
	ContextSHA      string `json:"context_sha256"`
	PromptSHA       string `json:"prompt_sha256"`
	InstructionsSHA string `json:"instructions_sha256"`
	Rules           string `json:"rules"`
}

type Options struct {
	Experiment, State string
	Offline           bool
	Replay            []byte
	Model             *Config
	Prices            []byte
	Budget            *state.BudgetConfig
}

func put(ctx context.Context, s *state.Store, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	a, err := s.Put(ctx, b, "application/json")
	if err != nil {
		return "", err
	}
	return a.SHA, nil
}

func decode(ctx context.Context, s *state.Store, sha string, v any) error {
	b, err := s.Get(ctx, sha)
	if err != nil {
		return err
	}
	return jsonx.Decode(b, v, false)
}

func addUnique(list []string, seen map[string]bool, v ...string) []string {
	for _, x := range v {
		if !seen[x] {
			seen[x] = true
			list = append(list, x)
		}
	}
	return list
}

// BuildContext derives the verifier's fresh context from a completed
// experiment run. It is deterministic for the same saved state, so an
// operator can compute the input identity before preparing a replay.
func BuildContext(ctx context.Context, dir string) (Context, *state.Snapshot, error) {
	c := Context{Schema: ContextSchema, PromptSHA: hash([]byte(prompt)), Claims: []Claim{}, Static: []Static{}, Excerpts: []recon.Excerpt{}, Declarations: []string{}, Gaps: []string{}}
	s, err := state.Open(ctx, dir)
	if err != nil {
		return c, nil, err
	}
	defer s.Close()
	snap, m, spec, err := experiment.Load(ctx, s)
	if err != nil {
		return c, nil, err
	}
	if snap.Run.Status != "completed" || len(snap.Reproductions) != 1 {
		return c, nil, fmt.Errorf("validation requires a completed experiment with a reproduction assessment")
	}
	if err := s.Verify(ctx, snap); err != nil {
		return c, nil, err
	}
	c.CandidateID, c.Canonical = m.CandidateID, m.CandidateCanonical
	excerpts, gaps := map[string]bool{}, map[string]bool{}
	for i, sha := range m.OccurrenceSHAs {
		var o hunt.Occurrence
		if err := decode(ctx, s, sha, &o); err != nil {
			return c, nil, err
		}
		var hc hunt.Context
		if err := decode(ctx, s, o.ContextSHA, &hc); err != nil {
			return c, nil, err
		}
		h := o.Hypothesis
		if i == 0 {
			c.Repository, c.RootCause, c.Anchor, c.Declarations = hc.Repository, h.RootCause, h.Anchor, hc.Declarations
		}
		c.Claims = append(c.Claims, ClaimsFor(i, h)...)
		st := Static{Entry: hc.Entry.Method.Class + "#" + hc.Entry.Method.Name + hc.Entry.Method.Descriptor, Execution: o.Static.Execution}
		if len(o.Static.Result) > 0 {
			var axes struct {
				Resolution string `json:"resolution"`
				Search     struct {
					State string `json:"state"`
				} `json:"search"`
				Model struct {
					State string `json:"state"`
				} `json:"model"`
			}
			if err := json.Unmarshal(o.Static.Result, &axes); err != nil {
				return c, nil, err
			}
			st.Resolution, st.Search, st.Model = axes.Resolution, axes.Search.State, axes.Model.State
		}
		c.Static = append(c.Static, st)
		for _, e := range hc.Excerpts {
			key := fmt.Sprintf("%s|%s|%d|%d", e.Path, e.SHA, e.Start, e.End)
			if !excerpts[key] {
				excerpts[key] = true
				c.Excerpts = append(c.Excerpts, e)
			}
		}
		c.Gaps = addUnique(c.Gaps, gaps, hc.Gaps...)
	}
	if len(c.Claims) == 0 {
		return c, nil, fmt.Errorf("experiment candidate has no recorded occurrence")
	}
	r := snap.Reproductions[0]
	var a experiment.Assessment
	if err := decode(ctx, s, r.PayloadSHA, &a); err != nil {
		return c, nil, err
	}
	c.Gaps = addUnique(c.Gaps, gaps, a.Gaps...)
	harness, err := s.Get(ctx, m.HarnessSHA)
	if err != nil {
		return c, nil, err
	}
	c.Experiment = ExperimentEvidence{Reproduction: r.Outcome, Reason: r.Reason, Property: spec.Property, HarnessName: m.HarnessName, Harness: string(harness), Cases: []CaseEvidence{}}
	if m.PatchSHA != "" {
		patch, err := s.Get(ctx, m.PatchSHA)
		if err != nil {
			return c, nil, err
		}
		c.Experiment.Patch = string(patch)
	}
	for _, cs := range a.Cases {
		var o experiment.Observation
		if err := decode(ctx, s, cs.ObservationSHA, &o); err != nil {
			return c, nil, err
		}
		e := CaseEvidence{ID: o.Case.ID, Role: o.Case.Role, Variant: o.Case.VariantName(), Description: o.Case.Description, Args: o.Case.Args, Outcome: o.Outcome, Assertion: o.Assertion, Escapes: o.Escapes}
		if o.Harness != nil {
			e.Exception = o.Harness.Exception
		}
		c.Experiment.Cases = append(c.Experiment.Cases, e)
	}
	c.Gaps = addUnique(c.Gaps, gaps, "the verifier sees bounded excerpts only; cross-class and runtime behavior outside them remain unexamined")
	c.Identity = identity(c)
	if b, _ := json.Marshal(c); len(b) > 96<<10 {
		return c, nil, fmt.Errorf("verifier context exceeds 96 KiB")
	}
	return c, snap, nil
}

// Start creates a derived validation run: a fresh-worker replay, one
// verifier task and a local decision. It runs nothing.
func Start(ctx context.Context, o Options) error {
	modes := 0
	for _, on := range []bool{o.Offline, o.Replay != nil, o.Model != nil} {
		if on {
			modes++
		}
	}
	if modes != 1 {
		return fmt.Errorf("select one verifier mode: offline, replay or model")
	}
	if o.Model != nil {
		c := o.Model
		if c.Schema != "tekmerion-validate-model-1" || !c.AllowSourceContext || o.Budget == nil || c.Model == "" || c.Provider == "" || c.MaxAttempts < 1 || c.MaxAttempts > 5 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > llm.MaxTimeoutSeconds || c.InputTokenBound <= 0 || c.MaxOutputTokens <= 0 {
			return fmt.Errorf("model validation requires bounded settings, source permission and its own explicit budget")
		}
		if err := llm.CheckReasoning(c.MaxOutputTokens, c.ReasoningMaxTokens, c.ReasoningEffort); err != nil {
			return err
		}
		p, err := pricing.ParseSnapshot(o.Prices)
		if err != nil {
			return err
		}
		if _, _, _, err = pricing.Bound(p, c.Model, c.Provider, c.InputTokenBound, c.MaxOutputTokens, time.Now()); err != nil {
			return err
		}
	}
	if o.Budget != nil {
		if err := o.Budget.Validate(); err != nil {
			return err
		}
	}
	c, snap, err := BuildContext(ctx, o.Experiment)
	if err != nil {
		return err
	}
	if o.Replay != nil {
		if _, err := ParseOutput(o.Replay, c); err != nil {
			return fmt.Errorf("verifier replay: %w", err)
		}
	}
	parent, err := state.Open(ctx, o.Experiment)
	if err != nil {
		return err
	}
	defer parent.Close()
	exp, err := filepath.Abs(o.Experiment)
	if err != nil {
		return err
	}
	s, err := state.Create(ctx, o.State)
	if err != nil {
		return err
	}
	defer s.Close()
	for _, a := range snap.Artifacts {
		raw, err := parent.Get(ctx, a.SHA)
		if err != nil {
			return err
		}
		if _, err := s.Put(ctx, raw, a.MediaType); err != nil {
			return err
		}
	}
	m := Manifest{Schema: RunSchema, Mode: "validate-offline", ParentRunID: snap.Run.ID, Experiment: exp, CandidateID: c.CandidateID, PromptSHA: hash([]byte(prompt)), Rules: Rules}
	if o.Replay != nil {
		m.Mode = "validate-replay"
	}
	if o.Model != nil {
		m.Mode = "validate-model"
	}
	if m.ParentSHA, err = put(ctx, s, snap); err != nil {
		return err
	}
	if m.ContextSHA, err = put(ctx, s, c); err != nil {
		return err
	}
	if _, err := s.Put(ctx, []byte(prompt), "text/plain"); err != nil {
		return err
	}
	a, err := s.Put(ctx, instructions, "application/json")
	if err != nil {
		return err
	}
	m.InstructionsSHA = a.SHA
	var input string
	switch {
	case o.Offline:
		input, err = put(ctx, s, Offline(c))
	case o.Replay != nil:
		a, err = s.Put(ctx, o.Replay, "application/json")
		if err == nil {
			input = a.SHA
		}
	default:
		cfg := o.Model
		b, _ := json.Marshal(c)
		if cfg.InputTokenBound < int64(len(prompt)+len(b)+256) {
			return fmt.Errorf("verifier token ceiling must cover context bytes plus framing")
		}
		prices, err := s.Put(ctx, o.Prices, "application/json")
		if err != nil {
			return err
		}
		t := gateway.Task{Schema: gateway.TaskSchema, Request: llm.Request{Role: "validate", Model: cfg.Model, Provider: cfg.Provider, ExpectedModel: cfg.ExpectedModel, ExpectedProvider: cfg.ExpectedProvider, PromptRevision: PromptRevision, Messages: []llm.Message{{Role: "system", Content: prompt}, {Role: "user", Content: string(b)}}, InputTokenBound: cfg.InputTokenBound, MaxOutputTokens: cfg.MaxOutputTokens, ReasoningMaxTokens: cfg.ReasoningMaxTokens, ReasoningEffort: cfg.ReasoningEffort, JSONOutput: true}, PricingSHA: prices.SHA, MaxAttempts: cfg.MaxAttempts, TimeoutSeconds: cfg.TimeoutSeconds}
		raw, _ := json.Marshal(t)
		if _, err := gateway.Parse(raw); err != nil {
			return err
		}
		input, err = put(ctx, s, t)
	}
	if err != nil {
		return err
	}
	tasks := []state.TaskInput{
		{ID: "replay", Stage: "experiment", InputSHA: m.ContextSHA},
		{ID: "validate", Stage: "validate", InputSHA: input, Paid: o.Model != nil},
		{ID: "decide", Stage: "decision", InputSHA: m.ContextSHA},
	}
	manifestSHA, err := put(ctx, s, m)
	if err != nil {
		return err
	}
	if o.Budget != nil {
		_, err = s.StartBudget(ctx, manifestSHA, tasks, *o.Budget)
	} else {
		_, err = s.Start(ctx, manifestSHA, tasks)
	}
	return err
}

func load(ctx context.Context, s *state.Store) (*state.Snapshot, Manifest, Context, error) {
	var m Manifest
	var c Context
	snap, err := s.Snapshot(ctx)
	if err != nil {
		return nil, m, c, err
	}
	if err := decode(ctx, s, snap.Run.ManifestSHA, &m); err != nil {
		return nil, m, c, err
	}
	if m.Schema != RunSchema || m.PromptSHA != hash([]byte(prompt)) || m.Rules != Rules {
		return nil, m, c, fmt.Errorf("validation protocol changed or wrong run")
	}
	if err := decode(ctx, s, m.ContextSHA, &c); err != nil {
		return nil, m, c, err
	}
	if c.Identity != identity(c) {
		return nil, m, c, fmt.Errorf("saved verifier context mismatch")
	}
	return snap, m, c, nil
}

func task(snap *state.Snapshot, id string) (state.Task, error) {
	for _, t := range snap.Tasks {
		if t.ID == id {
			return t, nil
		}
	}
	return state.Task{}, fmt.Errorf("missing task %s", id)
}

func worker() string { return "validate-" + rand.Text() }

// verifierRaw returns the accepted verifier output of a completed task.
func verifierRaw(ctx context.Context, s *state.Store, t state.Task, sha string) ([]byte, string, error) {
	raw, err := s.Get(ctx, sha)
	if err != nil {
		return nil, "", err
	}
	if !t.Paid {
		return raw, sha, nil
	}
	var ex gateway.Execution
	if err := jsonx.Decode(raw, &ex, false); err != nil {
		return nil, "", err
	}
	if ex.Result == nil {
		return nil, "", fmt.Errorf("missing saved verifier model result")
	}
	return []byte(ex.Result.Content), sha, nil
}

// Resume runs the replay, the verifier and the decision. Completed work is
// never repeated; a paid verifier needs a provider only while unfinished.
func Resume(ctx context.Context, dir string, provider llm.Provider) error {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	snap, m, c, err := load(ctx, s)
	if err != nil {
		return err
	}
	if snap.Run.Status != "running" {
		return nil
	}
	var parent state.Snapshot
	if err := decode(ctx, s, m.ParentSHA, &parent); err != nil {
		return err
	}
	var em experiment.Manifest
	if err := decode(ctx, s, parent.Run.ManifestSHA, &em); err != nil {
		return err
	}
	if t, err := task(snap, "replay"); err != nil {
		return err
	} else if t.Status != "completed" {
		raw, err := s.Get(ctx, em.SpecSHA)
		if err != nil {
			return err
		}
		spec, err := experiment.ParseSpec(raw)
		if err != nil {
			return err
		}
		var variant *experiment.VariantRecord
		if sha, ok := experiment.Completed(&parent, "correction"); ok {
			variant = &experiment.VariantRecord{}
			if err := decode(ctx, s, sha, variant); err != nil {
				return err
			}
		}
		lease := time.Duration(int64(len(spec.Cases)+2)*spec.Limits.WallSeconds)*time.Second + 5*time.Minute
		claim, err := s.Claim(ctx, snap.Run.ID, "replay", worker(), lease)
		if err != nil {
			return err
		}
		r, err := experiment.Replay(ctx, s, dir, em, spec, variant, "replay", claim.Number)
		if err != nil {
			outcome := "failed"
			if ctx.Err() != nil {
				outcome = "interrupted"
			}
			if e := s.Finish(context.Background(), *claim, outcome, "", err.Error()); e != nil {
				return fmt.Errorf("%v (recording it failed: %v)", err, e)
			}
			return err
		}
		sha, err := put(ctx, s, r)
		if err != nil {
			return err
		}
		if err := s.Finish(ctx, *claim, "completed", sha, ""); err != nil {
			return err
		}
	}
	if snap, err = s.Snapshot(ctx); err != nil {
		return err
	}
	vt, err := task(snap, "validate")
	if err != nil {
		return err
	}
	if vt.Status == "failed" {
		return fmt.Errorf("verifier task failed; inspect its diagnostic")
	}
	if vt.Status != "completed" {
		if vt.Paid {
			if provider == nil {
				return fmt.Errorf("unfinished paid verifier needs a model provider")
			}
			if _, err := gateway.Execute(ctx, s, vt.ID, provider, func(content string) error { _, err := ParseOutput([]byte(content), c); return err }); err != nil {
				return err
			}
		} else {
			claim, err := s.Claim(ctx, snap.Run.ID, vt.ID, worker(), time.Minute)
			if err != nil {
				return err
			}
			raw, err := s.Get(ctx, vt.InputSHA)
			if err != nil {
				return err
			}
			if _, err := ParseOutput(raw, c); err != nil {
				if e := s.Finish(ctx, *claim, "failed", vt.InputSHA, err.Error()); e != nil {
					return e
				}
				return err
			}
			if err := s.Finish(ctx, *claim, "completed", vt.InputSHA, ""); err != nil {
				return err
			}
		}
		if snap, err = s.Snapshot(ctx); err != nil {
			return err
		}
	}
	if t, err := task(snap, "decide"); err != nil || t.Status == "completed" {
		return err
	}
	outSHA, ok := experiment.Completed(snap, "validate")
	if !ok {
		return fmt.Errorf("verifier has no accepted output")
	}
	raw, outSHA, err := verifierRaw(ctx, s, vt, outSHA)
	if err != nil {
		return err
	}
	o, err := ParseOutput(raw, c)
	if err != nil {
		return err
	}
	replaySHA, _ := experiment.Completed(snap, "replay")
	var rr experiment.ReplayResult
	if err := decode(ctx, s, replaySHA, &rr); err != nil {
		return err
	}
	d := Decision{Schema: DecisionSchema, CandidateID: c.CandidateID, Reproduction: c.Experiment.Reproduction, Replay: rr.Assessment.Outcome, OutputSHA: outSHA, ReplaySHA: replaySHA, ExperimentRunID: m.ParentRunID}
	decide(&d, o)
	claim, err := s.Claim(ctx, snap.Run.ID, "decide", worker(), time.Minute)
	if err != nil {
		return err
	}
	sha, err := put(ctx, s, d)
	if err != nil {
		return err
	}
	return s.CommitDecision(ctx, *claim, sha, state.Decision{TaskID: "decide", CandidateID: d.CandidateID, Label: d.Label, Verifier: d.Verifier, Rules: d.Rules, Reason: d.Reason, PayloadSHA: sha})
}

// ClaimsFor splits occurrence i's hypothesis into the claim ids a verifier
// must assess: principal, resource, controlled input, each condition,
// mechanism and effect.
func ClaimsFor(i int, h hunt.Candidate) []Claim {
	p := "o" + strconv.Itoa(i+1) + "."
	fact := func(f recon.Fact) string { return f.Text + " (origin: " + f.Origin + ")" }
	out := []Claim{{ID: p + "principal", Text: fact(h.Principal)}, {ID: p + "resource", Text: fact(h.Resource)}, {ID: p + "controlled_input", Text: fact(h.ControlledInput)}}
	for k, f := range h.Conditions {
		out = append(out, Claim{ID: p + "condition-" + strconv.Itoa(k+1), Text: fact(f)})
	}
	return append(out, Claim{ID: p + "mechanism", Text: h.Invariant + " — " + h.Mechanism + " (" + h.MechanismKey + ")"}, Claim{ID: p + "effect", Text: h.Prediction})
}

// Summary is the saved outcome of one validation run.
type Summary struct {
	Manifest    Manifest
	Context     Context
	Output      *Output
	OutputSHA   string
	Decision    *Decision
	DecisionSHA string
	Replay      *experiment.ReplayResult
	ReplaySHA   string
}

// Summarize reads a validation run's saved results; missing parts stay nil.
func Summarize(ctx context.Context, s *state.Store) (*state.Snapshot, *Summary, error) {
	snap, m, c, err := load(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	r := &Summary{Manifest: m, Context: c}
	if sha, ok := experiment.Completed(snap, "replay"); ok {
		r.Replay, r.ReplaySHA = &experiment.ReplayResult{}, sha
		if err := decode(ctx, s, sha, r.Replay); err != nil {
			return nil, nil, err
		}
	}
	if sha, ok := experiment.Completed(snap, "validate"); ok {
		vt, err := task(snap, "validate")
		if err != nil {
			return nil, nil, err
		}
		raw, outSHA, err := verifierRaw(ctx, s, vt, sha)
		if err != nil {
			return nil, nil, err
		}
		o, err := ParseOutput(raw, c)
		if err != nil {
			return nil, nil, err
		}
		r.Output, r.OutputSHA = &o, outSHA
	}
	if len(snap.Decisions) == 1 {
		r.Decision, r.DecisionSHA = &Decision{}, snap.Decisions[0].PayloadSHA
		if err := decode(ctx, s, r.DecisionSHA, r.Decision); err != nil {
			return nil, nil, err
		}
	}
	return snap, r, nil
}
