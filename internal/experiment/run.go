package experiment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/sandbox"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type CaseJob struct {
	TaskID  string `json:"task_id"`
	CaseSHA string `json:"case_sha256"`
}

type Manifest struct {
	Schema             string    `json:"schema_version"`
	Mode               string    `json:"mode"`
	ParentSHA          string    `json:"parent_snapshot_sha256"`
	ParentRunID        string    `json:"parent_run_id"`
	PreparedSHA        string    `json:"prepared_manifest_sha256"`
	Work               string    `json:"prepared_work"`
	CandidateID        string    `json:"candidate_id"`
	CandidateCanonical string    `json:"candidate_canonical"`
	OccurrenceSHAs     []string  `json:"occurrence_sha256s"`
	SpecSHA            string    `json:"spec_sha256"`
	HarnessSHA         string    `json:"harness_sha256"`
	HarnessName        string    `json:"harness_name"`
	PatchSHA           string    `json:"patch_sha256,omitempty"`
	Classpath          []string  `json:"classpath"`
	Cases              []CaseJob `json:"cases"`
}

type Options struct {
	Hunt, Work, Spec, Candidate, State string
}

func hash(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }

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

// Start creates a derived experiment run for one Hunt candidate. It runs
// nothing: the sandbox probe, the cases and the assessment are queued tasks.
func Start(ctx context.Context, o Options) error {
	if o.Hunt == "" || o.Work == "" || o.Spec == "" || o.Candidate == "" || o.State == "" {
		return fmt.Errorf("experiment requires hunt state, prepared work, spec, candidate and new state")
	}
	specRaw, err := os.ReadFile(o.Spec)
	if err != nil {
		return err
	}
	spec, err := ParseSpec(specRaw)
	if err != nil {
		return err
	}
	harnessPath := spec.Harness
	if !filepath.IsAbs(harnessPath) {
		harnessPath = filepath.Join(filepath.Dir(o.Spec), harnessPath)
	}
	harness, err := os.ReadFile(harnessPath)
	if err != nil {
		return err
	}
	if len(harness) > 256<<10 || !utf8.Valid(harness) {
		return fmt.Errorf("harness must be UTF-8 Java source of at most 256 KiB")
	}
	parent, err := state.Open(ctx, o.Hunt)
	if err != nil {
		return err
	}
	defer parent.Close()
	snap, err := parent.Snapshot(ctx)
	if err != nil {
		return err
	}
	// A finished Hunt run is "failed" when some unit's Hunt task failed and was
	// recorded as blocked coverage; its accepted candidates remain usable.
	if snap.Run.Status != "completed" && snap.Run.Status != "failed" {
		return fmt.Errorf("experiment requires a finished Hunt run")
	}
	if err := parent.Verify(ctx, snap); err != nil {
		return err
	}
	var hm hunt.Manifest
	if err := decode(ctx, parent, snap.Run.ManifestSHA, &hm); err != nil {
		return fmt.Errorf("experiment parent must be a Hunt run: %w", err)
	}
	if hm.Schema != hunt.RunSchema {
		return fmt.Errorf("experiment parent must be a Hunt run")
	}
	m := Manifest{Schema: RunSchema, Mode: "checked-in-harness", ParentRunID: snap.Run.ID, PreparedSHA: hm.PreparedSHA, CandidateID: o.Candidate, OccurrenceSHAs: []string{}, HarnessName: spec.HarnessName, Cases: []CaseJob{}}
	for _, c := range snap.Candidates {
		if c.ID == o.Candidate {
			m.CandidateCanonical = c.Canonical
		}
	}
	if m.CandidateCanonical == "" {
		return fmt.Errorf("candidate %s not found in Hunt run", o.Candidate)
	}
	for _, oc := range snap.Occurrences {
		if oc.CandidateID == o.Candidate {
			m.OccurrenceSHAs = append(m.OccurrenceSHAs, oc.PayloadSHA)
		}
	}
	v, err := prepare.Verify(o.Work)
	if err != nil {
		return err
	}
	if hash(v.RawManifest) != hm.PreparedSHA {
		return fmt.Errorf("prepared target differs from the Hunt run's preparation")
	}
	m.Classpath = append([]string{}, v.Run.Artifacts.Classpath...)
	for _, p := range m.Classpath {
		if filepath.IsAbs(p) || p != filepath.Clean(p) || strings.HasPrefix(p, "..") || strings.ContainsAny(p, ":\n") {
			return fmt.Errorf("unsupported classpath entry %q", p)
		}
	}
	if m.Work, err = filepath.Abs(o.Work); err != nil {
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
	if m.ParentSHA, err = put(ctx, s, snap); err != nil {
		return err
	}
	a, err := s.Put(ctx, specRaw, "application/json")
	if err != nil {
		return err
	}
	m.SpecSHA = a.SHA
	if a, err = s.Put(ctx, harness, "text/x-java"); err != nil {
		return err
	}
	m.HarnessSHA = a.SHA
	tasks := []state.TaskInput{{ID: "capabilities", Stage: "experiment-setup", InputSHA: m.SpecSHA}}
	if spec.Correction != nil {
		patchPath := spec.Correction.Patch
		if !filepath.IsAbs(patchPath) {
			patchPath = filepath.Join(filepath.Dir(o.Spec), patchPath)
		}
		patch, err := os.ReadFile(patchPath)
		if err != nil {
			return err
		}
		if len(patch) == 0 || len(patch) > 256<<10 || !utf8.Valid(patch) {
			return fmt.Errorf("correction patch must be non-empty UTF-8 of at most 256 KiB")
		}
		if a, err = s.Put(ctx, patch, "text/x-diff"); err != nil {
			return err
		}
		m.PatchSHA = a.SHA
		tasks = append(tasks, state.TaskInput{ID: "correction", Stage: "experiment-setup", InputSHA: m.PatchSHA})
	}
	for _, c := range spec.Cases {
		sha, err := put(ctx, s, c)
		if err != nil {
			return err
		}
		job := CaseJob{TaskID: "case-" + c.ID, CaseSHA: sha}
		m.Cases = append(m.Cases, job)
		tasks = append(tasks, state.TaskInput{ID: job.TaskID, Stage: "experiment", InputSHA: sha})
	}
	tasks = append(tasks, state.TaskInput{ID: "assess", Stage: "assessment", InputSHA: m.SpecSHA})
	manifestSHA, err := put(ctx, s, m)
	if err != nil {
		return err
	}
	_, err = s.Start(ctx, manifestSHA, tasks)
	return err
}

// HarnessReport is the harness's own account of the call. It classifies
// exceptions only; the assertion never depends on it.
type HarnessReport struct {
	Schema    string `json:"schema_version"`
	Invoked   string `json:"invoked"`
	Exception string `json:"exception"`
}

type Observation struct {
	Schema       string         `json:"schema_version"`
	TaskID       string         `json:"task_id"`
	Attempt      int            `json:"attempt"`
	Case         Case           `json:"case"`
	Outcome      string         `json:"outcome"`
	Assertion    string         `json:"assertion"`
	Escapes      []string       `json:"entries_outside_confinement"`
	Reason       string         `json:"reason"`
	Harness      *HarnessReport `json:"harness_report,omitempty"`
	SandboxSHA   string         `json:"sandbox_result_sha256,omitempty"`
	Listing      *Listing       `json:"case_listing,omitempty"`
	TmpListing   *Listing       `json:"tmp_listing,omitempty"`
	TargetBefore string         `json:"prepared_manifest_before,omitempty"`
	TargetAfter  string         `json:"prepared_manifest_after,omitempty"`
}

func load(ctx context.Context, s *state.Store) (*state.Snapshot, Manifest, Spec, error) {
	var m Manifest
	var spec Spec
	snap, err := s.Snapshot(ctx)
	if err != nil {
		return nil, m, spec, err
	}
	if err := decode(ctx, s, snap.Run.ManifestSHA, &m); err != nil {
		return nil, m, spec, err
	}
	if m.Schema != RunSchema {
		return nil, m, spec, fmt.Errorf("not an experiment run")
	}
	raw, err := s.Get(ctx, m.SpecSHA)
	if err != nil {
		return nil, m, spec, err
	}
	spec, err = ParseSpec(raw)
	return snap, m, spec, err
}

func task(snap *state.Snapshot, id string) (state.Task, error) {
	for _, t := range snap.Tasks {
		if t.ID == id {
			return t, nil
		}
	}
	return state.Task{}, fmt.Errorf("missing task %s", id)
}

func completed(snap *state.Snapshot, id string) (string, bool) {
	for _, a := range snap.Attempts {
		if a.TaskID == id && a.Outcome == "completed" {
			return a.ResultSHA, true
		}
	}
	return "", false
}

func worker() string { return "experiment-" + rand.Text() }

// Resume runs the remaining tasks in order. Completed work is never rerun; an
// interrupted case reruns in a fresh scratch directory as a new attempt.
func Resume(ctx context.Context, dir string) error {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	snap, m, spec, err := load(ctx, s)
	if err != nil {
		return err
	}
	if snap.Run.Status != "running" {
		return nil
	}
	lease := time.Duration(spec.Limits.WallSeconds)*time.Second + 2*time.Minute
	// Worker scratch lives beside the ledger; each attempt gets a fresh directory.
	if err := os.MkdirAll(filepath.Join(dir, "scratch"), 0700); err != nil {
		return err
	}
	if t, err := task(snap, "capabilities"); err != nil {
		return err
	} else if t.Status != "completed" {
		claim, err := s.Claim(ctx, snap.Run.ID, t.ID, worker(), lease)
		if err != nil {
			return err
		}
		caps, err := sandbox.Probe(ctx, spec.Limits, filepath.Join(dir, "scratch", "capabilities-"+strconv.Itoa(claim.Number)))
		if err != nil {
			return finishErr(s, *claim, err)
		}
		sha, err := put(ctx, s, caps)
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
	capsSHA, _ := completed(snap, "capabilities")
	var caps sandbox.Capabilities
	if err := decode(ctx, s, capsSHA, &caps); err != nil {
		return err
	}
	var variant *VariantRecord
	if m.PatchSHA != "" {
		if variant, err = correction(ctx, s, dir, snap, m, caps); err != nil {
			return err
		}
		if snap, err = s.Snapshot(ctx); err != nil {
			return err
		}
	}
	for _, job := range m.Cases {
		t, err := task(snap, job.TaskID)
		if err != nil {
			return err
		}
		if t.Status == "completed" {
			continue
		}
		if t.Status == "failed" {
			return fmt.Errorf("experiment case %s failed; inspect its diagnostic", job.TaskID)
		}
		var c Case
		if err := decode(ctx, s, job.CaseSHA, &c); err != nil {
			return err
		}
		claim, err := s.Claim(ctx, snap.Run.ID, job.TaskID, worker(), lease)
		if err != nil {
			return err
		}
		obs, err := runCase(ctx, s, dir, m, spec, caps, variant, c, *claim)
		if err != nil {
			return finishErr(s, *claim, err)
		}
		sha, err := put(ctx, s, obs)
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
	if t, err := task(snap, "assess"); err != nil || t.Status == "completed" {
		return err
	}
	a := Assessment{Schema: AssessSchema, CandidateID: m.CandidateID, CapabilitiesSHA: capsSHA, Defect: "candidate", Novelty: "undetermined", Cases: []CaseSummary{}}
	for _, job := range m.Cases {
		sha, ok := completed(snap, job.TaskID)
		if !ok {
			return fmt.Errorf("case %s has no completed observation", job.TaskID)
		}
		var o Observation
		if err := decode(ctx, s, sha, &o); err != nil {
			return err
		}
		a.Cases = append(a.Cases, CaseSummary{TaskID: job.TaskID, CaseID: o.Case.ID, Role: o.Case.Role, Variant: o.Case.VariantName(), Outcome: o.Outcome, Assertion: o.Assertion, ObservationSHA: sha})
	}
	assess(&a)
	claim, err := s.Claim(ctx, snap.Run.ID, "assess", worker(), time.Minute)
	if err != nil {
		return err
	}
	sha, err := put(ctx, s, a)
	if err != nil {
		return err
	}
	return s.CommitReproduction(ctx, *claim, sha, state.Reproduction{TaskID: "assess", CandidateID: a.CandidateID, Outcome: a.Outcome, Reason: a.Reason, PayloadSHA: sha})
}

// finishErr retains a host-side failure as an immutable diagnostic. A
// cancelled context leaves the attempt interrupted so resume can retry it.
func finishErr(s *state.Store, c state.Claim, cause error) error {
	outcome := "failed"
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		outcome = "interrupted"
	}
	if err := s.Finish(context.Background(), c, outcome, "", cause.Error()); err != nil {
		return fmt.Errorf("%v (recording it failed: %v)", cause, err)
	}
	return cause
}

func preparedSHA(work string) (string, error) {
	v, err := prepare.Verify(work)
	if err != nil {
		return "", err
	}
	return hash(v.RawManifest), nil
}

func runCase(ctx context.Context, s *state.Store, dir string, m Manifest, spec Spec, caps sandbox.Capabilities, variant *VariantRecord, c Case, claim state.Claim) (Observation, error) {
	o := Observation{Schema: CaseSchema, TaskID: claim.TaskID, Attempt: claim.Number, Case: c, Assertion: "not_evaluated", Escapes: []string{}}
	if !caps.OK {
		failed := []string{}
		for _, v := range caps.Checks {
			if !v.OK {
				failed = append(failed, v.Name)
			}
		}
		if caps.Error != "" {
			failed = append(failed, caps.Error)
		}
		o.Outcome, o.Reason = "blocked", "sandbox capabilities not established: "+strings.Join(failed, "; ")
		return o, nil
	}
	before, err := preparedSHA(m.Work)
	o.TargetBefore = before
	if err != nil || before != m.PreparedSHA {
		o.Outcome, o.Reason = "invalidated", fmt.Sprintf("prepared target does not match the run before execution: %v", err)
		return o, nil
	}
	target, classpath := filepath.Join(m.Work, "out"), m.Classpath
	checkVariant := func() error { return nil }
	if c.VariantName() == Corrected {
		if variant == nil || variant.Variant == nil {
			reason := "no corrected variant was recorded"
			if variant != nil {
				reason = variant.Error
			}
			o.Outcome, o.Reason = "variant_unavailable", "corrected variant unavailable: "+reason
			return o, nil
		}
		target, classpath = filepath.Join(variant.Dir, "out"), variant.Variant.Artifacts.Classpath
		checkVariant = func() error { return prepare.CheckVariant(variant.Dir, variant.Variant, variant.Outputs) }
		if err := checkVariant(); err != nil {
			o.Outcome, o.Reason = "invalidated", "corrected variant does not match its record before execution: "+err.Error()
			return o, nil
		}
	}
	scratch := filepath.Join(dir, "scratch", fmt.Sprintf("%s-%d", claim.TaskID, claim.Number))
	caseDir, tmpDir := filepath.Join(scratch, "case"), filepath.Join(scratch, "tmp")
	if err := os.MkdirAll(filepath.Join(caseDir, "jail"), 0700); err != nil {
		return o, err
	}
	if err := os.Mkdir(tmpDir, 0700); err != nil {
		return o, err
	}
	harnessHost := filepath.Join(dir, "artifacts", strings.TrimPrefix(m.HarnessSHA, "sha256:"))
	if _, err := s.Get(ctx, m.HarnessSHA); err != nil {
		return o, err
	}
	cp := make([]string, len(classpath))
	for i, p := range classpath {
		if filepath.IsAbs(p) || p != filepath.Clean(p) || strings.HasPrefix(p, "..") || strings.ContainsAny(p, ":\n") {
			return o, fmt.Errorf("unsupported classpath entry %q", p)
		}
		cp[i] = "/target/" + filepath.ToSlash(p)
	}
	argv := []string{"java", "-XX:-UsePerfData", "-XX:+UseSerialGC", "-XX:TieredStopAtLevel=1", "-Xss1m", fmt.Sprintf("-Xmx%dm", spec.HeapMB), "-Djava.io.tmpdir=/tmp",
		"-cp", strings.Join(cp, ":"), "/harness/" + m.HarnessName, "/case/jail"}
	argv = append(argv, c.Args...)
	r, err := sandbox.Run(ctx, sandbox.Spec{Argv: argv, Dir: "/case", Tmp: tmpDir, Limits: spec.Limits, Mounts: []sandbox.Mount{
		{Host: target, Path: "/target"},
		{Host: harnessHost, Path: "/harness/" + m.HarnessName},
		{Host: caseDir, Path: "/case", Writable: true},
	}})
	if err != nil {
		return o, err
	}
	if o.SandboxSHA, err = put(ctx, s, r); err != nil {
		return o, err
	}
	after, err := preparedSHA(m.Work)
	o.TargetAfter = after
	if err != nil || after != m.PreparedSHA {
		o.Outcome, o.Reason = "invalidated", fmt.Sprintf("prepared target changed during the experiment: %v", err)
		return o, nil
	}
	if err := checkVariant(); err != nil {
		o.Outcome, o.Reason = "invalidated", "corrected variant changed during the experiment: "+err.Error()
		return o, nil
	}
	promote := func(_ string, b []byte) (string, error) {
		a, err := s.Put(ctx, b, "application/octet-stream")
		if err != nil {
			return "", err
		}
		return a.SHA, nil
	}
	// /case and /tmp are the only writable locations in the worker; anything
	// there outside the confinement directory is an escape.
	listing, err := Observe(caseDir, promote)
	if err != nil {
		return o, err
	}
	tmp, err := Observe(tmpDir, promote)
	if err != nil {
		return o, err
	}
	o.Listing, o.TmpListing = &listing, &tmp
	for _, e := range listing.Entries {
		if e.Path != "jail" && !strings.HasPrefix(e.Path, "jail/") {
			o.Escapes = append(o.Escapes, "/case/"+e.Path)
		}
	}
	for _, e := range tmp.Entries {
		o.Escapes = append(o.Escapes, "/tmp/"+e.Path)
	}
	sort.Strings(o.Escapes)
	o.Assertion = "held"
	if len(o.Escapes) > 0 {
		o.Assertion = "violated"
	}
	if listing.Truncated || tmp.Truncated {
		o.Assertion = "not_evaluated"
	}
	o.Harness, err = harnessReport(r.Stdout)
	o.Outcome, o.Reason = classify(r, o.Harness, err, o.Assertion)
	return o, nil
}

func harnessReport(stdout []byte) (*HarnessReport, error) {
	lines := bytes.Split(bytes.TrimSpace(stdout), []byte("\n"))
	last := lines[len(lines)-1]
	var h HarnessReport
	if err := jsonx.Decode(last, &h, false); err != nil {
		return nil, fmt.Errorf("harness report: %w", err)
	}
	if h.Schema != HarnessSchema || h.Invoked == "" {
		return nil, fmt.Errorf("harness report must be %s and name the invoked API", HarnessSchema)
	}
	return &h, nil
}

// classify combines the worker's termination, the harness report and the
// host assertion. Any doubt about the run outranks the assertion.
func classify(r *sandbox.Result, h *HarnessReport, herr error, assertion string) (string, string) {
	switch {
	case r.TimedOut:
		return "timeout", fmt.Sprintf("wall limit of %d s reached; assertion %s", r.Limits.WallSeconds, assertion)
	case r.Signal != "":
		return "resource_limit", fmt.Sprintf("worker terminated by signal %s (memory, task or CPU limit, not distinguished); assertion %s", r.Signal, assertion)
	case r.Exit != 0:
		return "harness_error", fmt.Sprintf("harness exited with status %d; assertion %s", r.Exit, assertion)
	case herr != nil:
		return "harness_error", herr.Error() + "; assertion " + assertion
	case assertion == "not_evaluated":
		return "harness_error", "worker output exceeded the observation bounds"
	case assertion == "violated":
		return "property_violated", "entries created outside the confinement directory after calling " + h.Invoked
	case h.Exception != "":
		return "target_exception", "target raised " + h.Exception + "; no entry outside the confinement directory in /case or /tmp"
	}
	return "property_held", "no entry outside the confinement directory after calling " + h.Invoked
}

type CaseSummary struct {
	TaskID         string `json:"task_id"`
	CaseID         string `json:"case_id"`
	Role           string `json:"role"`
	Variant        string `json:"variant"`
	Outcome        string `json:"outcome"`
	Assertion      string `json:"assertion"`
	ObservationSHA string `json:"observation_sha256"`
}

type Assessment struct {
	Schema          string        `json:"schema_version"`
	CandidateID     string        `json:"candidate_id"`
	Outcome         string        `json:"reproduction"`
	Reason          string        `json:"reason"`
	Defect          string        `json:"defect"`
	Novelty         string        `json:"novelty"`
	CapabilitiesSHA string        `json:"capabilities_sha256"`
	Cases           []CaseSummary `json:"cases"`
	Gaps            []string      `json:"gaps"`
}

// PendingVerificationGap is true of an experiment run and false inside the
// validation run that performs that verification, which drops it.
const PendingVerificationGap = "independent verification (RH-T5) has not run; defect remains candidate"

// assess derives the reproduction axis with fixed rules: every candidate case
// must violate the property while every normal and control case holds it.
// It never changes the defect or novelty axes.
func assess(a *Assessment) {
	a.Gaps = []string{
		"the assertion observes file creation in the worker's only writable locations (/case and /tmp); writes elsewhere are refused by the read-only sandbox and surface as target exceptions, not as violations",
		"the harness is checked in and supplied by the operator; it is not independently reviewed in this run",
		PendingVerificationGap,
	}
	roles := map[string]bool{}
	var blocked, invalid, unclear []string
	allViolated, allHeld, othersHeld := true, true, true
	for _, c := range a.Cases {
		roles[c.Role] = true
		switch c.Outcome {
		case "blocked":
			blocked = append(blocked, c.CaseID)
		case "invalidated":
			invalid = append(invalid, c.CaseID)
		}
		// A control may preserve the property by rejecting the input, so its
		// target exception counts as holding when the assertion held.
		controlHeld := c.Role == "control" && c.Outcome == "target_exception" && c.Assertion == "held"
		if c.Role == "candidate" {
			allViolated = allViolated && c.Outcome == "property_violated"
			allHeld = allHeld && c.Outcome == "property_held"
			if c.Outcome != "property_violated" && c.Outcome != "property_held" {
				unclear = append(unclear, c.CaseID+"="+c.Outcome)
			}
		} else if c.Outcome != "property_held" && !controlHeld {
			othersHeld = false
			unclear = append(unclear, c.CaseID+"="+c.Outcome)
		}
	}
	if !roles["control"] {
		a.Gaps = append(a.Gaps, "no property-preserving control case was supplied")
	}
	for _, c := range a.Cases {
		if c.Role == "control" && c.Variant == Corrected {
			a.Gaps = append(a.Gaps, "the corrected control uses an operator-supplied patch of the same revision; the patch is recorded but not independently reviewed")
			break
		}
	}
	switch {
	case len(blocked) > 0:
		a.Outcome, a.Reason = "blocked", "sandbox capabilities were not established; no target code ran"
	case len(invalid) > 0:
		a.Outcome, a.Reason = "inconclusive", "prepared target did not match the run for cases: "+strings.Join(invalid, ", ")
	case allViolated && othersHeld:
		a.Outcome, a.Reason = "reproduced", "every candidate case created entries outside the confinement directory while every normal/control case held the property"
	case allHeld && othersHeld:
		a.Outcome, a.Reason = "not_reproduced", "every case held the property within the observed scope; the prediction was not observed"
	default:
		a.Outcome, a.Reason = "inconclusive", "mixed or unclear case outcomes: "+strings.Join(unclear, ", ")
	}
}

const VariantRecordSchema = "tekmerion-variant-record-1"

// VariantRecord is the correction task's result. A patch that does not apply
// or a failed build is recorded, not hidden: control cases on the corrected
// variant then report variant_unavailable.
type VariantRecord struct {
	Schema  string            `json:"schema_version"`
	Dir     string            `json:"dir"`
	Variant *prepare.Variant  `json:"variant,omitempty"`
	Outputs manifest.Outputs  `json:"outputs"`
	Sources map[string]string `json:"corrected_sources"`
	Error   string            `json:"error,omitempty"`
}

// correction builds the corrected variant once, outside the target sandbox,
// with the project's own recipe and network policy (as TM1 preparation).
func correction(ctx context.Context, s *state.Store, dir string, snap *state.Snapshot, m Manifest, caps sandbox.Capabilities) (*VariantRecord, error) {
	t, err := task(snap, "correction")
	if err != nil {
		return nil, err
	}
	if t.Status != "completed" {
		claim, err := s.Claim(ctx, snap.Run.ID, t.ID, worker(), 30*time.Minute)
		if err != nil {
			return nil, err
		}
		rec := VariantRecord{Schema: VariantRecordSchema, Dir: filepath.Join(dir, "variants", fmt.Sprintf("corrected-%d", claim.Number)), Sources: map[string]string{}}
		v, err := prepare.Verify(m.Work)
		switch {
		case !caps.OK:
			rec.Error = "not built: sandbox capabilities were not established"
		case err != nil || hash(v.RawManifest) != m.PreparedSHA:
			rec.Error = fmt.Sprintf("not built: prepared target does not match the run (%v)", err)
		default:
			rec.Outputs = v.Project.Build.Outputs
			patch, err := s.Get(ctx, m.PatchSHA)
			if err != nil {
				return nil, finishErr(s, *claim, err)
			}
			if err := os.MkdirAll(filepath.Dir(rec.Dir), 0700); err != nil {
				return nil, finishErr(s, *claim, err)
			}
			built, err := prepare.BuildVariant(ctx, v, patch, rec.Dir, io.Discard)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, finishErr(s, *claim, err)
			}
			if err != nil {
				rec.Error = err.Error()
			} else {
				rec.Variant = built
				for _, f := range built.Changed {
					if !strings.HasPrefix(f.After, "sha256:") {
						continue
					}
					raw, err := prepare.ReadFile(filepath.Join(rec.Dir, "src"), f.Path, 2<<20)
					if err != nil {
						return nil, finishErr(s, *claim, err)
					}
					a, err := s.Put(ctx, raw, "text/plain")
					if err != nil || a.SHA != f.After {
						return nil, finishErr(s, *claim, fmt.Errorf("corrected source %s changed while recording (%v)", f.Path, err))
					}
					rec.Sources[f.Path] = a.SHA
				}
			}
		}
		sha, err := put(ctx, s, rec)
		if err != nil {
			return nil, err
		}
		if err := s.Finish(ctx, *claim, "completed", sha, ""); err != nil {
			return nil, err
		}
		return &rec, nil
	}
	sha, _ := completed(snap, "correction")
	var rec VariantRecord
	if err := decode(ctx, s, sha, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

const ReplaySchema = "tekmerion-replay-1"

// ReplayResult is a fresh-worker rerun of every case of a saved experiment.
type ReplayResult struct {
	Schema          string        `json:"schema_version"`
	CapabilitiesSHA string        `json:"capabilities_sha256"`
	Assessment      Assessment    `json:"assessment"`
	Cases           []CaseSummary `json:"cases"`
}

// Replay probes the sandbox again and reruns every case in fresh workers and
// fresh scratch directories under dir, saving evidence in s. s must hold the
// experiment's spec, harness and patch artifacts (a derived run copies them).
// The original experiment's observations are never read.
func Replay(ctx context.Context, s *state.Store, dir string, m Manifest, spec Spec, variant *VariantRecord, prefix string, attempt int) (*ReplayResult, error) {
	scratch := filepath.Join(dir, "scratch")
	if err := os.MkdirAll(scratch, 0700); err != nil {
		return nil, err
	}
	caps, err := sandbox.Probe(ctx, spec.Limits, filepath.Join(scratch, fmt.Sprintf("%s-capabilities-%d", prefix, attempt)))
	if err != nil {
		return nil, err
	}
	r := &ReplayResult{Schema: ReplaySchema, Cases: []CaseSummary{}}
	if r.CapabilitiesSHA, err = put(ctx, s, caps); err != nil {
		return nil, err
	}
	a := Assessment{Schema: AssessSchema, CandidateID: m.CandidateID, CapabilitiesSHA: r.CapabilitiesSHA, Defect: "candidate", Novelty: "undetermined", Cases: []CaseSummary{}}
	for _, c := range spec.Cases {
		claim := state.Claim{TaskID: prefix + "-" + c.ID, Number: attempt}
		o, err := runCase(ctx, s, dir, m, spec, *caps, variant, c, claim)
		if err != nil {
			return nil, err
		}
		sha, err := put(ctx, s, o)
		if err != nil {
			return nil, err
		}
		a.Cases = append(a.Cases, CaseSummary{TaskID: claim.TaskID, CaseID: c.ID, Role: c.Role, Variant: c.VariantName(), Outcome: o.Outcome, Assertion: o.Assertion, ObservationSHA: sha})
	}
	assess(&a)
	r.Assessment, r.Cases = a, a.Cases
	return r, nil
}

// Load reads a saved experiment run's snapshot, manifest and spec.
func Load(ctx context.Context, s *state.Store) (*state.Snapshot, Manifest, Spec, error) {
	return load(ctx, s)
}

// Completed returns the accepted result artifact of a task.
func Completed(snap *state.Snapshot, id string) (string, bool) { return completed(snap, id) }
