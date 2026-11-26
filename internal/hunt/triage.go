package hunt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type StaticAssessment struct {
	Execution       string `json:"execution"`
	Diagnostic      string `json:"diagnostic,omitempty"`
	Provenance      string `json:"provenance,omitempty"`
	ValidationScope string `json:"validation_scope,omitempty"`
	RequestSHA      string `json:"request_sha256,omitempty"`
	ResponseSHA     string `json:"response_sha256,omitempty"`
	StderrSHA       string `json:"stderr_sha256,omitempty"`
	AttemptSHA      string `json:"attempt_sha256,omitempty"`
	// The full per-target result preserves resolution, search, model, dispatch,
	// completeness, entries, path edges and their provenance without flattening.
	Result json.RawMessage `json:"accepted_result,omitempty"`
}
type Occurrence struct {
	Schema       string           `json:"schema_version"`
	CandidateID  string           `json:"candidate_id"`
	UnitID       string           `json:"unit_id"`
	ContextSHA   string           `json:"context_sha256"`
	OutputSHA    string           `json:"output_sha256"`
	Hypothesis   Candidate        `json:"hypothesis"`
	Defect       string           `json:"defect"`
	Reproduction string           `json:"reproduction"`
	Novelty      string           `json:"novelty"`
	Static       StaticAssessment `json:"static"`
}
type Projection struct {
	Schema     string           `json:"schema_version"`
	ContextSHA string           `json:"context_sha256"`
	OutputSHA  string           `json:"output_sha256"`
	Commit     state.HuntCommit `json:"commit"`
}

func triage(ctx context.Context, s *state.Store, claim state.Claim, m Manifest, job Job, c Context, o Output, q ariadne.Querier) error {
	outputSHA, err := put(ctx, s, o)
	if err != nil {
		return err
	}
	status := o.Conclusion
	if status == "candidates" {
		status = "candidate"
	}
	if status == "no_candidate" {
		status = "checked"
	}
	commit := state.HuntCommit{Candidates: []state.Candidate{}, Occurrences: []state.CandidateOccurrence{}, Event: state.CoverageEvent{UnitID: c.Unit.ID, TaskID: claim.TaskID, Status: status, Reason: o.Reason, PayloadSHA: outputSHA}}
	if len(o.Candidates) > 0 {
		assessments, err := assess(ctx, s, m, c, o.Candidates, q)
		if err != nil {
			return err
		}
		for i, candidate := range o.Candidates {
			id, canonical := fingerprint(c, candidate)
			occurrence := Occurrence{Schema: "tekmerion-hunt-occurrence-1", CandidateID: id, UnitID: c.Unit.ID, ContextSHA: job.ContextSHA, OutputSHA: outputSHA, Hypothesis: candidate, Defect: "candidate", Reproduction: "not_run", Novelty: "undetermined", Static: assessments[i]}
			payloadSHA, err := put(ctx, s, occurrence)
			if err != nil {
				return err
			}
			commit.Candidates = append(commit.Candidates, state.Candidate{ID: id, Canonical: canonical, SourceIdentity: c.Unit.SourceIdentity, PayloadSHA: payloadSHA})
			commit.Occurrences = append(commit.Occurrences, state.CandidateOccurrence{CandidateID: id, UnitID: c.Unit.ID, TaskID: claim.TaskID, PayloadSHA: payloadSHA})
		}
	}
	projection := Projection{Schema: "tekmerion-hunt-projection-1", ContextSHA: job.ContextSHA, OutputSHA: outputSHA, Commit: commit}
	resultSHA, err := put(ctx, s, projection)
	if err != nil {
		return err
	}
	return s.CommitHunt(ctx, claim, resultSHA, commit)
}
func assess(ctx context.Context, s *state.Store, m Manifest, c Context, candidates []Candidate, q ariadne.Querier) ([]StaticAssessment, error) {
	out := make([]StaticAssessment, len(candidates))
	blocked := func(reason string) ([]StaticAssessment, error) {
		for i := range out {
			out[i] = StaticAssessment{Execution: "unavailable", Diagnostic: reason}
		}
		return out, nil
	}
	v, err := prepare.Verify(m.Work)
	if err != nil {
		return blocked("prepared bundle unavailable or changed: " + err.Error())
	}
	if hash(v.RawManifest) != m.PreparedSHA || v.Run.Analysis == nil || v.Run.Analysis.AnalysisID != c.AnalysisID {
		return blocked("preparation identity differs from saved Hunt context")
	}
	if len(c.Entry.RootNodes) == 0 {
		return blocked("entry has no indexed root nodes")
	}
	if q == nil {
		return blocked("Ariadne adapter unavailable")
	}
	targets := []map[string]any{}
	for _, candidate := range candidates {
		var target Method
		for _, t := range c.Methods {
			if t.ID == candidate.TargetID {
				target = t
			}
		}
		targets = append(targets, map[string]any{"id": candidate.LocalID, "selector": map[string]string{"instance_id": target.InstanceID, "class": target.Method.Class, "name": target.Method.Name, "descriptor": target.Method.Descriptor}})
	}
	request, _ := json.Marshal(map[string]any{"schema_version": ariadne.QuerySchema, "analysis_id": c.AnalysisID, "request_id": "hunt-" + c.Unit.ID[7:23], "operation": "reachability", "roots": map[string]any{"selection": "subset", "node_ids": c.Entry.RootNodes}, "targets": targets, "limits": map[string]int{"max_entries": 16, "max_path_nodes": 128, "max_work_units": 100000}})
	requestArtifact, err := s.Put(ctx, request, "application/json")
	if err != nil {
		return nil, err
	}
	timeout, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res, queryErr := q.Query(timeout, request)
	base := StaticAssessment{Execution: "unavailable", RequestSHA: requestArtifact.SHA}
	if queryErr != nil {
		base.Diagnostic = queryErr.Error()
	}
	if res != nil {
		base.Provenance = res.Provenance
		base.ValidationScope = res.ValidationScope
		for _, item := range []struct {
			raw   []byte
			dest  *string
			media string
		}{{res.RawResponse, &base.ResponseSHA, "application/json"}, {res.Stderr, &base.StderrSHA, "text/plain"}} {
			if len(item.raw) > 0 {
				a, err := s.Put(ctx, item.raw, item.media)
				if err != nil {
					return nil, err
				}
				*item.dest = a.SHA
			}
		}
		if res.Dir != "" {
			raw, err := prepare.ReadFile(res.Dir, "attempt.json", 1<<20)
			if err != nil {
				return nil, err
			}
			a, err := s.Put(ctx, raw, "application/json")
			if err != nil {
				return nil, err
			}
			base.AttemptSHA = a.SHA
		}
	}
	for i := range out {
		out[i] = base
	}
	if queryErr != nil || res == nil || res.Outcome != ariadne.OutcomeResult || res.ValidationScope != "bundle" {
		if base.Diagnostic == "" {
			for i := range out {
				out[i].Diagnostic = "query produced no bundle-validated reachability result"
			}
		}
		return out, nil
	}
	head, err := ariadne.ParseRequest(request)
	if err != nil {
		return nil, err
	}
	if _, err = ariadne.Check(head, res.Exit, res.RawResponse); err != nil {
		for i := range out {
			out[i].Diagnostic = "adapter result failed revalidation: " + err.Error()
		}
		return out, nil
	}
	// Recheck preparation after reading evidence, before admitting any graph facts.
	fresh, err := prepare.Verify(m.Work)
	if err != nil || hash(fresh.RawManifest) != m.PreparedSHA {
		for i := range out {
			out[i].Diagnostic = "prepared evidence changed during query"
		}
		return out, nil
	}
	var envelope struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(res.RawResponse, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Results) != len(candidates) {
		return nil, fmt.Errorf("validated result count changed")
	}
	for i, raw := range envelope.Results {
		out[i].Execution = "completed"
		out[i].Diagnostic = ""
		out[i].Result = raw
	}
	return out, nil
}
