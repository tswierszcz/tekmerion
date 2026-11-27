package recon

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type Manifest struct {
	Schema       string `json:"schema_version"`
	Mode         string `json:"mode"`
	ContextSHA   string `json:"context_sha256"`
	InventorySHA string `json:"inventory_sha256"`
	PreparedSHA  string `json:"prepared_manifest_sha256"`
	PromptSHA    string `json:"prompt_sha256"`
	CatalogueSHA string `json:"catalogue_sha256"`
	Limits       Limits `json:"limits"`
}
type Config struct {
	Schema             string `json:"schema_version"`
	Model              string `json:"model"`
	Provider           string `json:"provider"`
	ExpectedModel      string `json:"expected_returned_model,omitempty"`
	ExpectedProvider   string `json:"expected_returned_provider,omitempty"`
	InputTokenBound    int64  `json:"input_token_bound"`
	MaxOutputTokens    int64  `json:"max_output_tokens"`
	ReasoningMaxTokens int64  `json:"reasoning_max_tokens,omitempty"`
	ReasoningEffort    string `json:"reasoning_effort,omitempty"`
	MaxAttempts        int    `json:"max_attempts"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	AllowSourceContext bool   `json:"allow_source_context"`
}
type Options struct {
	Work, State string
	Limits      Limits
	Offline     bool
	Replay      []byte
	Model       *Config
	Prices      []byte
	Budget      *state.BudgetConfig
	Querier     ariadne.Querier
}

// Start snapshots verified preparation, bounded discovery and model input. It
// never contacts a model. Offline output is explicitly a deterministic baseline.
func Start(ctx context.Context, options Options) error {
	modes := 0
	if options.Offline {
		modes++
	}
	if options.Replay != nil {
		modes++
	}
	if options.Model != nil {
		modes++
	}
	if modes != 1 {
		return fmt.Errorf("select exactly one Recon mode: offline, replay or model")
	}
	if err := options.Limits.Validate(); err != nil {
		return err
	}
	if options.Model != nil {
		config := options.Model
		if config.Schema != "tekmerion-recon-model-1" || !config.AllowSourceContext || options.Budget == nil || config.Model == "" || config.Provider == "" || config.InputTokenBound <= 0 || config.MaxOutputTokens <= 0 || config.MaxAttempts < 1 || config.MaxAttempts > 5 || config.TimeoutSeconds < 1 || config.TimeoutSeconds > llm.MaxTimeoutSeconds {
			return fmt.Errorf("Recon model mode needs bounded settings, source-context permission and a budget")
		}
		if err := llm.CheckReasoning(config.MaxOutputTokens, config.ReasoningMaxTokens, config.ReasoningEffort); err != nil {
			return err
		}
		if err := options.Budget.Validate(); err != nil {
			return err
		}
		snapshot, err := pricing.ParseSnapshot(options.Prices)
		if err != nil {
			return err
		}
		if _, _, _, err := pricing.Bound(snapshot, config.Model, config.Provider, config.InputTokenBound, config.MaxOutputTokens, time.Now()); err != nil {
			return err
		}
	}
	if options.Querier == nil {
		return fmt.Errorf("Recon needs an Ariadne discovery adapter")
	}
	v, err := prepare.Verify(options.Work)
	if err != nil {
		return err
	}
	s, err := state.Create(ctx, options.State)
	if err != nil {
		return err
	}
	defer s.Close()
	inventory, err := Build(ctx, s, v, options.Querier, options.Limits)
	if err != nil {
		return err
	}
	put := func(raw []byte) (string, error) {
		a, err := s.Put(ctx, raw, "application/json")
		if err != nil {
			return "", err
		}
		return a.SHA, nil
	}
	contextRaw, err := json.Marshal(inventory.Context)
	if err != nil {
		return err
	}
	contextSHA, err := put(contextRaw)
	if err != nil {
		return err
	}
	inventoryRaw, err := json.Marshal(inventory.Entries)
	if err != nil {
		return err
	}
	inventorySHA, err := put(inventoryRaw)
	if err != nil {
		return err
	}
	mode := "recon-offline"
	var taskSHA string
	if options.Model == nil {
		response := options.Replay
		if options.Offline {
			baseline := Baseline(inventory.Context)
			response, err = json.Marshal(baseline)
			if err != nil {
				return err
			}
		} else {
			mode = "recon-replay"
		}
		// Preserve malformed replay inputs too; execution will reject them and
		// record the failed attempt rather than accepting unverifiable evidence.
		taskSHA, err = put(response)
		if err != nil {
			return err
		}
	} else {
		mode = "recon-model"
		config := options.Model
		if config.Schema != "tekmerion-recon-model-1" || !config.AllowSourceContext || options.Budget == nil {
			return fmt.Errorf("Recon model mode needs its config, explicit source context policy and budget")
		}
		if config.InputTokenBound < int64(len(prompt)+len(contextRaw)+256) {
			return fmt.Errorf("input ceiling must cover the context bytes plus declared framing allowance")
		}
		priceSHA, err := put(options.Prices)
		if err != nil {
			return err
		}
		request := llm.Request{Role: "recon", Model: config.Model, Provider: config.Provider, ExpectedModel: config.ExpectedModel, ExpectedProvider: config.ExpectedProvider, PromptRevision: PromptRevision, Messages: []llm.Message{{Role: "system", Content: prompt}, {Role: "user", Content: string(contextRaw)}}, InputTokenBound: config.InputTokenBound, MaxOutputTokens: config.MaxOutputTokens, ReasoningMaxTokens: config.ReasoningMaxTokens, ReasoningEffort: config.ReasoningEffort, JSONOutput: true}
		task := gateway.Task{Schema: gateway.TaskSchema, Request: request, PricingSHA: priceSHA, MaxAttempts: config.MaxAttempts, TimeoutSeconds: config.TimeoutSeconds}
		raw, err := json.Marshal(task)
		if err != nil {
			return err
		}
		if _, err := gateway.Parse(raw); err != nil {
			return err
		}
		taskSHA, err = put(raw)
		if err != nil {
			return err
		}
	}
	m := Manifest{Schema: RunSchema, Mode: mode, ContextSHA: contextSHA, InventorySHA: inventorySHA, PreparedSHA: hash(v.RawManifest), PromptSHA: hash([]byte(prompt)), CatalogueSHA: hash(catalogue), Limits: options.Limits}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	manifestSHA, err := put(raw)
	if err != nil {
		return err
	}
	tasks := []state.TaskInput{{ID: "recon", Stage: "recon", InputSHA: taskSHA, Paid: options.Model != nil}, {ID: "coverage", Stage: "coverage", InputSHA: contextSHA}}
	if options.Budget != nil {
		_, err = s.StartBudget(ctx, manifestSHA, tasks, *options.Budget)
	} else {
		_, err = s.Start(ctx, manifestSHA, tasks)
	}
	return err
}

// Baseline contains source/API metadata and explicit unknowns only. It is not
// model inference or a claim that a trust boundary has been investigated.
func Baseline(c Context) Output {
	o := Output{InputIdentity: c.Identity, Schema: ResultSchema, Summary: "Deterministic source/API inventory. Principal authority, intended filesystem scope and control semantics require research; no hypotheses were supplied or generated.", Principals: []Fact{}, Resources: []Fact{}, Inputs: []Fact{}, Transformations: []Fact{}, Controls: []Fact{}, Assumptions: []Fact{}, Coverage: []Proposal{}, Gaps: append([]string{}, c.Gaps...)}
	o.Gaps = append(o.Gaps, "offline baseline performs no semantic model analysis; file-confinement applicability remains unassessed")
	for _, d := range c.Declarations {
		o.Assumptions = append(o.Assumptions, Fact{Text: d, Origin: "user_declared", Citations: []Citation{}})
	}
	for _, entry := range c.Entries {
		proposal := Proposal{EntryID: entry.ID, PropertyID: "file-confinement", Status: "planned", Reason: "candidate property selected for later investigation; no check performed", Citations: []Citation{}}
		if entry.Source == nil {
			proposal.Status = "blocked"
			proposal.Reason = "exact source mapping unavailable"
		} else {
			for _, excerpt := range c.Excerpts {
				if excerpt.Path == entry.Source.Path && excerpt.SHA == entry.Source.SHA && excerpt.End >= entry.Source.Start && excerpt.Start <= entry.Source.End {
					proposal.Citations = append(proposal.Citations, excerpt.Citation)
					break
				}
			}
		}
		o.Coverage = append(o.Coverage, proposal)
	}
	return o
}
func ParseOutput(raw []byte, c Context) (Output, error) {
	var o Output
	if err := jsonx.Decode(raw, &o, false); err != nil {
		return o, err
	}
	return o, o.Validate(c)
}

// Resume only needs saved evidence for projection. After model completion a
// crash can resume without credentials or another model call.
func Resume(ctx context.Context, dir string, provider llm.Provider) error {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	snap, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	raw, err := s.Get(ctx, snap.Run.ManifestSHA)
	if err != nil {
		return err
	}
	var manifest Manifest
	if err := jsonx.Decode(raw, &manifest, false); err != nil {
		return err
	}
	if manifest.Schema != RunSchema || manifest.PromptSHA != hash([]byte(prompt)) || manifest.CatalogueSHA != hash(catalogue) {
		return fmt.Errorf("Recon protocol/catalogue changed; saved run cannot silently migrate")
	}
	if snap.Run.Status == "completed" {
		return nil
	}
	raw, err = s.Get(ctx, manifest.ContextSHA)
	if err != nil {
		return err
	}
	var c Context
	if err := jsonx.Decode(raw, &c, false); err != nil {
		return err
	}
	raw, err = s.Get(ctx, manifest.InventorySHA)
	if err != nil {
		return err
	}
	if c.Identity != contextIdentity(c) || c.Schema != ContextSchema || c.PreparedSHA != manifest.PreparedSHA || c.PromptSHA != manifest.PromptSHA || c.CatalogueSHA != manifest.CatalogueSHA {
		return fmt.Errorf("saved Recon context identity mismatch")
	}
	var inventory []Entry
	if err := jsonx.Decode(raw, &inventory, false); err != nil {
		return err
	}
	var reconTask *state.Task
	for i := range snap.Tasks {
		if snap.Tasks[i].ID == "recon" {
			reconTask = &snap.Tasks[i]
		}
	}
	if reconTask == nil {
		return fmt.Errorf("missing Recon task")
	}
	if reconTask.Status == "failed" {
		return fmt.Errorf("Recon failed; inspect saved diagnostics")
	}
	var output Output
	if reconTask.Status == "completed" {
		for _, a := range snap.Attempts {
			if a.TaskID == "recon" && a.Outcome == "completed" {
				raw, err := s.Get(ctx, a.ResultSHA)
				if err != nil {
					return err
				}
				if manifest.Mode == "recon-model" {
					var execution gateway.Execution
					if err := jsonx.Decode(raw, &execution, false); err != nil {
						return err
					}
					if execution.Result == nil {
						return fmt.Errorf("missing saved model output")
					}
					raw = []byte(execution.Result.Content)
				}
				output, err = ParseOutput(raw, c)
				if err != nil {
					return err
				}
			}
		}
	} else if manifest.Mode == "recon-model" {
		if provider == nil {
			return fmt.Errorf("unfinished model Recon requires a provider")
		}
		result, err := gateway.Execute(ctx, s, "recon", provider, func(content string) error { _, err := ParseOutput([]byte(content), c); return err })
		if err != nil {
			return err
		}
		output, err = ParseOutput([]byte(result.Content), c)
		if err != nil {
			return err
		}
	} else if manifest.Mode == "recon-offline" || manifest.Mode == "recon-replay" {
		claim, err := s.Claim(ctx, snap.Run.ID, "recon", "recon-local-"+rand.Text(), time.Minute)
		if err != nil {
			return err
		}
		raw, err := s.Get(ctx, reconTask.InputSHA)
		if err != nil {
			return err
		}
		output, err = ParseOutput(raw, c)
		if err != nil {
			if saveErr := s.Finish(ctx, *claim, "failed", reconTask.InputSHA, err.Error()); saveErr != nil {
				return saveErr
			}
			return err
		}
		if err := s.Finish(ctx, *claim, "completed", reconTask.InputSHA, ""); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unsupported Recon mode")
	}
	claim, err := s.Claim(ctx, snap.Run.ID, "coverage", "recon-project-"+rand.Text(), time.Minute)
	if err != nil {
		return err
	}
	return project(ctx, s, *claim, manifest, c, inventory, output)
}

type Projection struct {
	Schema     string               `json:"schema_version"`
	ContextSHA string               `json:"context_sha256"`
	OutputSHA  string               `json:"output_sha256"`
	Units      []state.CoverageSeed `json:"units"`
}

type UnitPayload struct {
	Entry         Entry    `json:"entry"`
	Proposal      Proposal `json:"proposal"`
	ContextSHA    string   `json:"context_sha256"`
	CatalogueSHA  string   `json:"catalogue_sha256"`
	BoundaryBasis string   `json:"boundary_basis"`
}

func canonicalUnit(c Context, entry Entry) (string, string) {
	refs := []string{c.Repository, methodKey(entry.Method), "caller-controlled-input=>filesystem-scope", entry.Subsystem, "file-confinement-1", "api-invocation", c.ScenarioSHA}
	raw, _ := json.Marshal(refs)
	return hash(raw), string(raw)
}
func project(ctx context.Context, s *state.Store, claim state.Claim, m Manifest, c Context, inventory []Entry, output Output) error {
	proposals := map[string]Proposal{}
	for _, p := range output.Coverage {
		proposals[p.EntryID] = p
	}
	seeds := []state.CoverageSeed{}
	for _, entry := range inventory {
		p, ok := proposals[entry.ID]
		if !ok {
			status, reason := "deferred", entry.SelectionReason
			if reason == "" {
				reason = "outside selected Recon context"
			}
			if entry.Source == nil {
				status = "blocked"
			}
			p = Proposal{EntryID: entry.ID, PropertyID: "file-confinement", Status: status, Reason: reason, Citations: []Citation{}}
		}
		id, canonical := canonicalUnit(c, entry)
		payload := UnitPayload{Entry: entry, Proposal: p, ContextSHA: m.ContextSHA, CatalogueSHA: m.CatalogueSHA, BoundaryBasis: "catalogue candidate boundary; not an observed authority failure"}
		raw, _ := json.Marshal(payload)
		a, err := s.Put(ctx, raw, "application/json")
		if err != nil {
			return err
		}
		seeds = append(seeds, state.CoverageSeed{ID: id, Canonical: canonical, SourceIdentity: stable(c.SourceSHA, c.AppSHA, c.AnalysisID, entry.Method.ClassSHA256), PayloadSHA: a.SHA, Status: p.Status, Reason: p.Reason})
	}
	sort.Slice(seeds, func(i, j int) bool { return seeds[i].ID < seeds[j].ID })
	outputRaw, err := json.Marshal(output)
	if err != nil {
		return err
	}
	o, err := s.Put(ctx, outputRaw, "application/json")
	if err != nil {
		return err
	}
	projection := Projection{Schema: "tekmerion-recon-projection-1", ContextSHA: m.ContextSHA, OutputSHA: o.SHA, Units: seeds}
	raw, err := json.Marshal(projection)
	if err != nil {
		return err
	}
	result, err := s.Put(ctx, raw, "application/json")
	if err != nil {
		return err
	}
	return s.CommitCoverage(ctx, claim, result.SHA, seeds)
}
