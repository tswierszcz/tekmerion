package hunt

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type Job struct {
	TaskID     string `json:"task_id"`
	TriageID   string `json:"triage_task_id"`
	ContextSHA string `json:"context_sha256"`
}
type Manifest struct {
	Schema        string   `json:"schema_version"`
	Mode          string   `json:"mode"`
	ParentSHA     string   `json:"parent_snapshot_sha256"`
	ParentRunID   string   `json:"parent_run_id"`
	PreparedSHA   string   `json:"prepared_manifest_sha256"`
	PromptSHA     string   `json:"prompt_sha256"`
	Work          string   `json:"prepared_work"`
	Binary        string   `json:"ariadne_binary"`
	SeedsSHA      string   `json:"coverage_seeds_sha256"`
	Jobs          []Job    `json:"jobs"`
	DeferredUnits []string `json:"deferred_unit_ids"`
}
type Config recon.Config

// Replay maps unit IDs to recorded outputs. The same strict validation applies
// to model and replay input; offline mode creates no semantic observations.
type Replay struct {
	Schema  string                     `json:"schema_version"`
	Outputs map[string]json.RawMessage `json:"outputs"`
}
type Options struct {
	Recon, Work, State, Binary string
	MaxUnits                   int
	Offline                    bool
	Replay                     []byte
	Model                      *Config
	Prices                     []byte
	Budget                     *state.BudgetConfig
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

// Start creates an explicit derived run and a finite queue. The parent's ledger
// is archived separately, not charged again or treated as a replenished budget.
// No model or reachability query is executed while constructing this queue.
func Start(ctx context.Context, o Options) error {
	modes := 0
	if o.Offline {
		modes++
	}
	if o.Replay != nil {
		modes++
	}
	if o.Model != nil {
		modes++
	}
	if modes != 1 || o.MaxUnits < 1 || o.MaxUnits > 64 {
		return fmt.Errorf("select one Hunt mode and max-units in 1..64")
	}
	if o.Model != nil {
		c := o.Model
		if c.Schema != "tekmerion-hunt-model-1" || !c.AllowSourceContext || o.Budget == nil || c.Model == "" || c.Provider == "" || c.MaxAttempts < 1 || c.MaxAttempts > 5 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 120 || c.InputTokenBound <= 0 || c.MaxOutputTokens <= 0 {
			return fmt.Errorf("model Hunt requires bounded settings, source permission and its own explicit budget")
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
	var replay Replay
	if o.Replay != nil {
		if err := jsonx.Decode(o.Replay, &replay, false); err != nil {
			return err
		}
		if replay.Schema != "tekmerion-hunt-replay-1" {
			return fmt.Errorf("unsupported Hunt replay schema")
		}
	}
	parent, err := state.Open(ctx, o.Recon)
	if err != nil {
		return err
	}
	defer parent.Close()
	snap, err := parent.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snap.Run.Status != "completed" {
		return fmt.Errorf("Hunt requires completed Recon")
	}
	if err := parent.Verify(ctx, snap); err != nil {
		return err
	}
	var rm recon.Manifest
	if err := decode(ctx, parent, snap.Run.ManifestSHA, &rm); err != nil {
		return err
	}
	if rm.Schema != recon.RunSchema {
		return fmt.Errorf("Hunt parent must be Recon")
	}
	var rc recon.Context
	if err := decode(ctx, parent, rm.ContextSHA, &rc); err != nil {
		return err
	}
	var architecture recon.Output
	found := false
	for _, a := range snap.Attempts {
		if a.TaskID == "coverage" && a.Outcome == "completed" {
			var projection recon.Projection
			if err := decode(ctx, parent, a.ResultSHA, &projection); err != nil {
				return err
			}
			raw, err := parent.Get(ctx, projection.OutputSHA)
			if err != nil {
				return err
			}
			architecture, err = recon.ParseOutput(raw, rc)
			if err != nil {
				return err
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("Recon has no validated coverage projection")
	}
	v, err := prepare.Verify(o.Work)
	if err != nil {
		return err
	}
	if v.Run.Analysis == nil || hash(v.RawManifest) != rm.PreparedSHA || rc.PreparedSHA != rm.PreparedSHA || rc.SourceSHA != v.Run.Source.TreeSHA256 || rc.AppSHA != v.Run.Artifacts.App.SHA256 || rc.AnalysisID != v.Run.Analysis.AnalysisID {
		return fmt.Errorf("prepared target differs from Recon; run Recon on new evidence")
	}
	o.Work, err = filepath.Abs(o.Work)
	if err != nil {
		return err
	}
	if o.Binary != "" {
		o.Binary, err = filepath.Abs(o.Binary)
		if err != nil {
			return err
		}
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
	parentSHA, err := put(ctx, s, snap)
	if err != nil {
		return err
	}
	seeds := []state.CoverageSeed{}
	for _, u := range snap.Coverage {
		seeds = append(seeds, u.CoverageSeed)
	}
	seedsSHA, err := put(ctx, s, seeds)
	if err != nil {
		return err
	}
	m := Manifest{Schema: RunSchema, Mode: "hunt-offline", ParentSHA: parentSHA, ParentRunID: snap.Run.ID, PreparedSHA: rm.PreparedSHA, PromptSHA: hash([]byte(prompt)), Work: o.Work, Binary: o.Binary, SeedsSHA: seedsSHA, Jobs: []Job{}, DeferredUnits: []string{}}
	if o.Replay != nil {
		m.Mode = "hunt-replay"
	}
	if o.Model != nil {
		m.Mode = "hunt-model"
	}
	if _, err := s.Put(ctx, []byte(prompt), "text/plain"); err != nil {
		return err
	}
	tasks := []state.TaskInput{{ID: "coverage", Stage: "coverage", InputSHA: seedsSHA}}
	selected := map[string]bool{}
	for _, u := range snap.Coverage {
		if u.Status != "planned" {
			continue
		}
		if len(m.Jobs) >= o.MaxUnits {
			m.DeferredUnits = append(m.DeferredUnits, u.ID)
			continue
		}
		var unit recon.UnitPayload
		if err := decode(ctx, s, u.PayloadSHA, &unit); err != nil {
			return err
		}
		c, err := buildContext(ctx, s, v, rc, architecture, u.CoverageSeed, unit)
		if err != nil {
			return err
		}
		csha, err := put(ctx, s, c)
		if err != nil {
			return err
		}
		taskID := fmt.Sprintf("hunt-%03d", len(m.Jobs)+1)
		triageID := fmt.Sprintf("triage-%03d", len(m.Jobs)+1)
		var inputSHA string
		if o.Model == nil {
			raw := replay.Outputs[u.ID]
			if o.Offline {
				raw, _ = json.Marshal(Output{Schema: ResultSchema, InputIdentity: c.Identity, Conclusion: "deferred", Reason: "offline mode performs no semantic Hunt; source context is ready for model or recorded review", Checks: []Check{}, Candidates: []Candidate{}, Gaps: c.Gaps})
			} else if raw == nil {
				return fmt.Errorf("replay missing selected unit %s", u.ID)
			}
			a, err := s.Put(ctx, raw, "application/json")
			if err != nil {
				return err
			}
			inputSHA = a.SHA
		} else {
			config := o.Model
			b, _ := json.Marshal(c)
			if config.InputTokenBound < int64(len(prompt)+len(b)+256) {
				return fmt.Errorf("Hunt token ceiling must cover source context bytes plus framing")
			}
			prices, err := s.Put(ctx, o.Prices, "application/json")
			if err != nil {
				return err
			}
			t := gateway.Task{Schema: gateway.TaskSchema, Request: llm.Request{Role: "hunt", Model: config.Model, Provider: config.Provider, ExpectedModel: config.ExpectedModel, ExpectedProvider: config.ExpectedProvider, PromptRevision: PromptRevision, Messages: []llm.Message{{Role: "system", Content: prompt}, {Role: "user", Content: string(b)}}, InputTokenBound: config.InputTokenBound, MaxOutputTokens: config.MaxOutputTokens, JSONOutput: true}, PricingSHA: prices.SHA, MaxAttempts: config.MaxAttempts, TimeoutSeconds: config.TimeoutSeconds}
			raw, _ := json.Marshal(t)
			if _, err := gateway.Parse(raw); err != nil {
				return err
			}
			inputSHA, err = put(ctx, s, t)
			if err != nil {
				return err
			}
		}
		m.Jobs = append(m.Jobs, Job{TaskID: taskID, TriageID: triageID, ContextSHA: csha})
		tasks = append(tasks, state.TaskInput{ID: taskID, Stage: "hunt", InputSHA: inputSHA, Paid: o.Model != nil}, state.TaskInput{ID: triageID, Stage: "triage", InputSHA: csha})
		selected[u.ID] = true
	}
	for id := range replay.Outputs {
		if !selected[id] {
			return fmt.Errorf("replay supplied unknown or unselected unit %s", id)
		}
	}
	fresh, err := prepare.Verify(o.Work)
	if err != nil {
		return err
	}
	if hash(fresh.RawManifest) != rm.PreparedSHA {
		return fmt.Errorf("preparation changed while snapshotting Hunt")
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

// Expansion is deliberately limited to the entry's exact class-file identity.
// Cross-class callees require a future logged context expansion, not invented code.
func buildContext(ctx context.Context, s *state.Store, v *prepare.Verified, rc recon.Context, architecture recon.Output, u state.CoverageSeed, p recon.UnitPayload) (Context, error) {
	c := Context{Schema: ContextSchema, ParentContextSHA: p.ContextSHA, Unit: u, Entry: p.Entry, Repository: rc.Repository, AnalysisID: rc.AnalysisID, PreparedSHA: rc.PreparedSHA, PromptSHA: hash([]byte(prompt)), Methods: []Method{}, Excerpts: []recon.Excerpt{}, Declarations: rc.Declarations, Recon: architecture, Gaps: append([]string{}, architecture.Gaps...)}
	c.Gaps = append(c.Gaps, "Hunt context expands at most 16 methods from the exact entry class; cross-class and runtime behavior remain unexamined", "source review and graph reachability do not establish caller authority or a reproduced security effect")
	entries := append([]sourceindex.Entry{}, v.Index.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		ai := a.Name == p.Entry.Method.Name && a.Descriptor == p.Entry.Method.Descriptor
		bi := b.Name == p.Entry.Method.Name && b.Descriptor == p.Entry.Method.Descriptor
		if ai != bi {
			return ai
		}
		return a.Name+a.Descriptor < b.Name+b.Descriptor
	})
	artifacts := map[string]string{v.Run.Artifacts.App.Path: v.Run.Artifacts.App.SHA256}
	for _, a := range v.Run.Artifacts.Deps {
		artifacts[a.Path] = a.SHA256
	}
	seenMethods := map[string]bool{}
	for _, e := range entries {
		if artifacts[e.Artifact] != p.Entry.ArtifactSHA {
			continue
		}
		if e.Class != p.Entry.Method.Class || e.ClassSHA256 != p.Entry.Method.ClassSHA256 {
			continue
		}
		if len(c.Methods) >= 16 {
			c.Gaps = append(c.Gaps, "same-class method limit reached")
			break
		}
		if e.Binding != sourceindex.BindingBuildVerified || e.Path == nil || e.SourceSHA256 == nil || e.LineStart == nil || e.LineEnd == nil {
			c.Gaps = append(c.Gaps, "unavailable exact source binding: "+e.Class+"#"+e.Name+e.Descriptor)
			continue
		}
		raw, err := prepare.ReadFile(v.Work+"/src", *e.Path, 2<<20)
		if err != nil {
			return c, err
		}
		if hash(raw) != *e.SourceSHA256 || !utf8.Valid(raw) {
			return c, fmt.Errorf("Hunt source changed or is not UTF-8")
		}
		lines := strings.Split(string(raw), "\n")
		start, end := max(1, *e.LineStart-4), *e.LineEnd
		if end < start || end > len(lines) {
			return c, fmt.Errorf("invalid indexed method range")
		}
		end = min(end, start+79)
		m := sourceindex.Method{Class: e.Class, Name: e.Name, Descriptor: e.Descriptor, ClassSHA256: e.ClassSHA256}
		key, _ := json.Marshal([]string{p.Entry.InstanceID, methodKey(m), m.ClassSHA256})
		if seenMethods[hash(key)] {
			continue
		}
		seenMethods[hash(key)] = true
		method := Method{ID: hash(key), Method: m, InstanceID: p.Entry.InstanceID, Source: recon.Citation{Path: *e.Path, SHA: *e.SourceSHA256, Start: *e.LineStart, End: *e.LineEnd}}
		excerpt := recon.Excerpt{Kind: "method", Citation: recon.Citation{Path: *e.Path, SHA: *e.SourceSHA256, Start: start, End: end}, Text: strings.Join(lines[start-1:end], "\n")}
		c.Methods = append(c.Methods, method)
		c.Excerpts = append(c.Excerpts, excerpt)
		b, _ := json.Marshal(c)
		if len(b) > 60<<10 {
			c.Methods = c.Methods[:len(c.Methods)-1]
			c.Excerpts = c.Excerpts[:len(c.Excerpts)-1]
			c.Gaps = append(c.Gaps, "Hunt context byte limit reached")
			break
		}
		if end < *e.LineEnd {
			c.Gaps = append(c.Gaps, "method excerpt truncated: "+methodKey(m))
		}
		if _, err := s.Put(ctx, raw, "text/x-java"); err != nil {
			return c, err
		}
	}
	for _, e := range rc.Excerpts {
		if e.Kind == "method" {
			continue
		}
		c.Excerpts = append(c.Excerpts, e)
		b, _ := json.Marshal(c)
		if len(b) > 62<<10 {
			c.Excerpts = c.Excerpts[:len(c.Excerpts)-1]
			c.Gaps = append(c.Gaps, "documentation/test excerpt context limit")
			break
		}
	}
	if len(c.Methods) == 0 {
		return c, fmt.Errorf("planned unit has no verified bounded source methods")
	}
	c.Identity = identity(c)
	b, _ := json.Marshal(c)
	if len(b) > 64<<10 {
		return c, fmt.Errorf("Hunt context exceeds 64 KiB")
	}
	return c, nil
}

func load(ctx context.Context, s *state.Store) (*state.Snapshot, Manifest, error) {
	snap, err := s.Snapshot(ctx)
	if err != nil {
		return nil, Manifest{}, err
	}
	var m Manifest
	err = decode(ctx, s, snap.Run.ManifestSHA, &m)
	if err == nil && (m.Schema != RunSchema || m.PromptSHA != hash([]byte(prompt))) {
		err = fmt.Errorf("Hunt protocol changed or wrong run")
	}
	return snap, m, err
}
func taskByID(snap *state.Snapshot, id string) (state.Task, error) {
	for _, t := range snap.Tasks {
		if t.ID == id {
			return t, nil
		}
	}
	return state.Task{}, fmt.Errorf("missing task %s", id)
}
func completedRaw(ctx context.Context, s *state.Store, snap *state.Snapshot, t state.Task) ([]byte, error) {
	for _, a := range snap.Attempts {
		if a.TaskID == t.ID && a.Outcome == "completed" {
			raw, err := s.Get(ctx, a.ResultSHA)
			if err != nil {
				return nil, err
			}
			if t.Paid {
				var ex gateway.Execution
				if err := jsonx.Decode(raw, &ex, false); err != nil {
					return nil, err
				}
				if ex.Result == nil {
					return nil, fmt.Errorf("missing saved Hunt model result")
				}
				raw = []byte(ex.Result.Content)
			}
			return raw, nil
		}
	}
	return nil, fmt.Errorf("missing completed Hunt evidence")
}

// Resume completes each Hunt/triage pair before admitting the next paid task.
// Completed model output is revalidated without another model request.
func Resume(ctx context.Context, dir string, provider llm.Provider, q ariadne.Querier) error {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	snap, m, err := load(ctx, s)
	if err != nil {
		return err
	}
	if snap.Run.Status == "completed" {
		return nil
	}
	if q == nil && m.Binary != "" {
		q = &ariadne.CLI{Binary: m.Binary, Bundle: filepath.Join(m.Work, "bundle"), Evidence: ariadne.Recorder{Root: filepath.Join(dir, "ariadne-invocations")}}
	}
	coverage, err := taskByID(snap, "coverage")
	if err != nil {
		return err
	}
	if coverage.Status != "completed" {
		claim, err := s.Claim(ctx, snap.Run.ID, "coverage", "hunt-import-"+rand.Text(), time.Minute)
		if err != nil {
			return err
		}
		var seeds []state.CoverageSeed
		if err := decode(ctx, s, m.SeedsSHA, &seeds); err != nil {
			return err
		}
		if err := s.CommitCoverage(ctx, *claim, m.SeedsSHA, seeds); err != nil {
			return err
		}
	}
	for _, job := range m.Jobs {
		snap, err = s.Snapshot(ctx)
		if err != nil {
			return err
		}
		ht, err := taskByID(snap, job.TaskID)
		if err != nil {
			return err
		}
		tt, err := taskByID(snap, job.TriageID)
		if err != nil {
			return err
		}
		if tt.Status == "completed" {
			continue
		}
		if ht.Status == "failed" || tt.Status == "failed" {
			return fmt.Errorf("Hunt task failed; inspect immutable diagnostics")
		}
		var c Context
		if err := decode(ctx, s, job.ContextSHA, &c); err != nil {
			return err
		}
		if c.Identity != identity(c) {
			return fmt.Errorf("saved Hunt context mismatch")
		}
		var raw []byte
		if ht.Status == "completed" {
			raw, err = completedRaw(ctx, s, snap, ht)
		} else if ht.Paid {
			if provider == nil {
				return fmt.Errorf("unfinished paid Hunt needs a model provider")
			}
			r, e := gateway.Execute(ctx, s, ht.ID, provider, func(content string) error { _, err := ParseOutput([]byte(content), c); return err })
			err = e
			if err == nil {
				raw = []byte(r.Content)
			}
		} else {
			claim, e := s.Claim(ctx, snap.Run.ID, ht.ID, "hunt-local-"+rand.Text(), time.Minute)
			if e != nil {
				return e
			}
			raw, err = s.Get(ctx, ht.InputSHA)
			if err != nil {
				return err
			}
			_, err = ParseOutput(raw, c)
			if err != nil {
				if e := s.Finish(ctx, *claim, "failed", ht.InputSHA, err.Error()); e != nil {
					return e
				}
				return err
			}
			err = s.Finish(ctx, *claim, "completed", ht.InputSHA, "")
		}
		if err != nil {
			return err
		}
		output, err := ParseOutput(raw, c)
		if err != nil {
			return err
		}
		claim, err := s.Claim(ctx, snap.Run.ID, tt.ID, "hunt-triage-"+rand.Text(), 5*time.Minute)
		if err != nil {
			return err
		}
		if err := triage(ctx, s, *claim, m, job, c, output, q); err != nil {
			return err
		}
	}
	return nil
}
