package export

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/state"
	"github.com/tswierszcz/tekmerion/internal/validate"
)

type Options struct {
	Hunt        string
	Runs        []string
	Out         string
	Provenance  string
	GeneratedAt string
}

func hash(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }

func decode(ctx context.Context, s *state.Store, sha string, v any) error {
	b, err := s.Get(ctx, sha)
	if err != nil {
		return err
	}
	return jsonx.Decode(b, v, false)
}

type opened struct {
	dir    string
	s      *state.Store
	snap   *state.Snapshot
	schema string
	mode   string
	ref    RunRef
}

func openRun(ctx context.Context, dir string) (*opened, error) {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	snap, err := s.Snapshot(ctx)
	if err == nil {
		err = s.Verify(ctx, snap)
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	raw, err := s.Get(ctx, snap.Run.ManifestSHA)
	if err != nil {
		s.Close()
		return nil, err
	}
	var kind struct {
		Schema string `json:"schema_version"`
		Mode   string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		s.Close()
		return nil, err
	}
	b, _ := json.Marshal(snap)
	return &opened{dir: dir, s: s, snap: snap, schema: kind.Schema, mode: kind.Mode, ref: RunRef{RunID: snap.Run.ID, Status: snap.Run.Status, Mode: kind.Mode, SnapshotSHA: hash(b), Source: "state directory"}}, nil
}

// expSource is an experiment's saved state, either its own directory or the
// copy archived inside a validation run.
type expSource struct {
	s    *state.Store
	snap *state.Snapshot
	m    experiment.Manifest
	ref  RunRef
}

type review struct {
	o   *opened
	sum *validate.Summary
}

type builder struct {
	ctx      context.Context
	tmp      string
	media    map[string]string
	index    map[string]*IndexEntry
	files    map[string]string
	hunt     *opened
	hm       hunt.Manifest
	recon    *state.Snapshot
	exps     map[string]*expSource
	reviews  []review
	runs     []RunRef
	latestNs int64
}

type IndexEntry struct {
	SHA       string   `json:"sha256"`
	Path      string   `json:"path"`
	Size      int64    `json:"size"`
	MediaType string   `json:"media_type"`
	Roles     []string `json:"roles"`
}

type Index struct {
	Schema    string            `json:"schema_version"`
	Artifacts []IndexEntry      `json:"artifacts"`
	Files     map[string]string `json:"files"`
}

func (b *builder) note(snap *state.Snapshot) {
	for _, a := range snap.Artifacts {
		b.media[a.SHA] = a.MediaType
	}
	if snap.Run.CreatedAt > b.latestNs {
		b.latestNs = snap.Run.CreatedAt
	}
}

// add copies one hash-verified artifact into evidence/artifacts and returns
// its report-relative path.
func (b *builder) add(s *state.Store, sha, role string) (string, error) {
	if sha == "" {
		return "", nil
	}
	if e, ok := b.index[sha]; ok {
		for _, r := range e.Roles {
			if r == role {
				return e.Path, nil
			}
		}
		e.Roles = append(e.Roles, role)
		return e.Path, nil
	}
	raw, err := s.Get(b.ctx, sha)
	if err != nil {
		return "", err
	}
	rel := "evidence/artifacts/" + strings.TrimPrefix(sha, "sha256:")
	if err := os.WriteFile(filepath.Join(b.tmp, filepath.FromSlash(rel)), raw, 0o644); err != nil {
		return "", err
	}
	media := b.media[sha]
	if media == "" {
		media = "application/octet-stream"
	}
	b.index[sha] = &IndexEntry{SHA: sha, Path: rel, Size: int64(len(raw)), MediaType: media, Roles: []string{role}}
	return rel, nil
}

func (b *builder) write(rel string, raw []byte) error {
	p := filepath.Join(b.tmp, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b.files[rel] = hash(raw)
	return os.WriteFile(p, raw, 0o644)
}

// Export writes a complete export directory or nothing: the result is built
// in a sibling temporary directory, verified, and renamed into place.
func Export(ctx context.Context, o Options) error {
	if o.Hunt == "" || o.Out == "" {
		return fmt.Errorf("export needs a Hunt state and a new output directory")
	}
	if o.Provenance != "control" && o.Provenance != "real" {
		return fmt.Errorf("provenance must be control (a deliberately vulnerable control target) or real")
	}
	if _, err := os.Lstat(o.Out); err == nil {
		return fmt.Errorf("output %s already exists", o.Out)
	}
	tmp := o.Out + ".partial-" + rand.Text()
	if err := os.MkdirAll(filepath.Join(tmp, "evidence", "artifacts"), 0o755); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	b := &builder{ctx: ctx, tmp: tmp, media: map[string]string{}, index: map[string]*IndexEntry{}, files: map[string]string{}, exps: map[string]*expSource{}}
	defer b.close()
	r, err := b.build(o)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := b.write("report.json", append(raw, '\n')); err != nil {
		return err
	}
	if err := b.write("report.md", []byte(Markdown(r))); err != nil {
		return err
	}
	idx := Index{Schema: IndexSchema, Artifacts: []IndexEntry{}, Files: map[string]string{}}
	for _, e := range b.index {
		sort.Strings(e.Roles)
		idx.Artifacts = append(idx.Artifacts, *e)
	}
	sort.Slice(idx.Artifacts, func(i, j int) bool { return idx.Artifacts[i].SHA < idx.Artifacts[j].SHA })
	for k, v := range b.files {
		idx.Files[k] = v
	}
	raw, _ = json.MarshalIndent(idx, "", "  ")
	if err := b.write("evidence/index.json", append(raw, '\n')); err != nil {
		return err
	}
	if err := Verify(tmp); err != nil {
		return fmt.Errorf("export verification failed: %w", err)
	}
	if err := os.Rename(tmp, o.Out); err != nil {
		return err
	}
	ok = true
	return nil
}

// close closes every opened store once; archived experiments share the
// store of the validation run that holds them.
func (b *builder) close() {
	done := map[*state.Store]bool{}
	closeOnce := func(s *state.Store) {
		if s != nil && !done[s] {
			done[s] = true
			s.Close()
		}
	}
	if b.hunt != nil {
		closeOnce(b.hunt.s)
	}
	for _, v := range b.reviews {
		closeOnce(v.o.s)
	}
	for _, e := range b.exps {
		closeOnce(e.s)
	}
}

func (b *builder) build(o Options) (*Report, error) {
	ctx := b.ctx
	var err error
	if b.hunt, err = openRun(ctx, o.Hunt); err != nil {
		return nil, err
	}
	if b.hunt.schema != hunt.RunSchema {
		return nil, fmt.Errorf("%s is not a Hunt run", o.Hunt)
	}
	b.hunt.ref.Kind = "hunt"
	if err := decode(ctx, b.hunt.s, b.hunt.snap.Run.ManifestSHA, &b.hm); err != nil {
		return nil, err
	}
	b.note(b.hunt.snap)
	b.recon = &state.Snapshot{}
	if err := decode(ctx, b.hunt.s, b.hm.ParentSHA, b.recon); err != nil {
		return nil, err
	}
	var rm recon.Manifest
	if err := decode(ctx, b.hunt.s, b.recon.Run.ManifestSHA, &rm); err != nil {
		return nil, err
	}
	var rc recon.Context
	if err := decode(ctx, b.hunt.s, rm.ContextSHA, &rc); err != nil {
		return nil, err
	}
	b.runs = append(b.runs, RunRef{Kind: "recon", RunID: b.recon.Run.ID, Status: b.recon.Run.Status, Mode: rm.Mode, SnapshotSHA: b.hm.ParentSHA, Source: "archived in hunt run"}, b.hunt.ref)
	for _, dir := range o.Runs {
		run, err := openRun(ctx, dir)
		if err != nil {
			return nil, err
		}
		b.note(run.snap)
		switch run.schema {
		case experiment.RunSchema:
			_, m, _, err := experiment.Load(ctx, run.s)
			if err != nil {
				run.s.Close()
				return nil, err
			}
			if m.ParentRunID != b.hunt.snap.Run.ID {
				run.s.Close()
				return nil, fmt.Errorf("%s does not derive from this Hunt run", dir)
			}
			run.ref.Kind = "experiment"
			b.exps[run.snap.Run.ID] = &expSource{s: run.s, snap: run.snap, m: m, ref: run.ref}
		case validate.RunSchema:
			_, sum, err := validate.Summarize(ctx, run.s)
			if err != nil {
				run.s.Close()
				return nil, err
			}
			parent := &state.Snapshot{}
			if err := decode(ctx, run.s, sum.Manifest.ParentSHA, parent); err != nil {
				run.s.Close()
				return nil, err
			}
			var em experiment.Manifest
			if err := decode(ctx, run.s, parent.Run.ManifestSHA, &em); err != nil {
				run.s.Close()
				return nil, err
			}
			if em.ParentRunID != b.hunt.snap.Run.ID {
				run.s.Close()
				return nil, fmt.Errorf("%s does not derive from this Hunt run", dir)
			}
			run.ref.Kind = "validation"
			b.reviews = append(b.reviews, review{o: run, sum: sum})
			if _, have := b.exps[parent.Run.ID]; !have {
				// The validation run archives its parent experiment; use that
				// copy when the experiment directory itself is not supplied.
				b.exps[parent.Run.ID] = &expSource{s: run.s, snap: parent, m: em, ref: RunRef{Kind: "experiment", RunID: parent.Run.ID, Status: parent.Run.Status, Mode: em.Mode, SnapshotSHA: sum.Manifest.ParentSHA, Source: "archived in validation run " + run.snap.Run.ID}}
			}
		default:
			run.s.Close()
			return nil, fmt.Errorf("%s: only experiment and validation runs can be added to a Hunt export", dir)
		}
	}
	sort.Slice(b.reviews, func(i, j int) bool {
		a, c := b.reviews[i].o.snap.Run, b.reviews[j].o.snap.Run
		return a.CreatedAt < c.CreatedAt || a.CreatedAt == c.CreatedAt && a.ID < c.ID
	})
	expIDs := []string{}
	for id := range b.exps {
		expIDs = append(expIDs, id)
	}
	sort.Strings(expIDs)
	for _, id := range expIDs {
		b.runs = append(b.runs, b.exps[id].ref)
	}
	for _, v := range b.reviews {
		b.runs = append(b.runs, v.o.ref)
	}

	r := &Report{Schema: ReportSchema, Provenance: o.Provenance, Runs: b.runs, Findings: []Finding{}, Coverage: []Unit{}, Gaps: []string{}}
	r.GeneratedAt = o.GeneratedAt
	if r.GeneratedAt == "" {
		r.GeneratedAt = time.Unix(0, b.latestNs).UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, r.GeneratedAt); err != nil {
		return nil, fmt.Errorf("generated-at must be RFC3339: %w", err)
	}
	r.Target = Target{Repository: rc.Repository, Revision: rc.Revision, PreparedSHA: rc.PreparedSHA, SourceTree: rc.SourceSHA, App: rc.AppSHA, AnalysisID: rc.AnalysisID}
	if err := b.coverage(r); err != nil {
		return nil, err
	}
	for _, c := range b.hunt.snap.Candidates {
		f, err := b.finding(c)
		if err != nil {
			return nil, err
		}
		raw, _ := json.MarshalIndent(f, "", "  ")
		if err := b.write(f.Evidence+"/finding.json", append(raw, '\n')); err != nil {
			return nil, err
		}
		r.Findings = append(r.Findings, f)
	}
	b.summarize(r)
	return r, nil
}

func (b *builder) coverage(r *Report) error {
	events := map[string]state.CoverageEvent{}
	for _, e := range b.hunt.snap.CoverageHistory {
		events[e.UnitID] = e
	}
	outside := map[string]bool{}
	for _, id := range b.hm.DeferredUnits {
		outside[id] = true
	}
	for _, u := range b.hunt.snap.Coverage {
		cur, reason := u.Status, u.Reason
		if e, ok := events[u.ID]; ok {
			cur, reason = e.Status, e.Reason
		} else if outside[u.ID] {
			cur, reason = "deferred", "outside this Hunt wave's max-units"
		}
		r.Coverage = append(r.Coverage, Unit{ID: u.ID, Initial: u.Status, Current: cur, Reason: reason})
	}
	return nil
}

func (b *builder) finding(c state.Candidate) (Finding, error) {
	ctx, hs := b.ctx, b.hunt.s
	f := Finding{ID: c.ID, Canonical: c.Canonical, Origin: "discovery", Property: "file-confinement-1", Claims: []Claim{}, Occurrences: []Occurrence{}, Experiments: []Reproduction{}, Reviews: []Review{}, Unresolved: []string{}, Novelty: "undetermined"}
	f.Evidence = "evidence/findings/" + strings.TrimPrefix(c.ID, "sha256:")[:16]
	statics := []string{}
	n := 0
	for _, row := range b.hunt.snap.Occurrences {
		if row.CandidateID != c.ID {
			continue
		}
		var o hunt.Occurrence
		if err := decode(ctx, hs, row.PayloadSHA, &o); err != nil {
			return f, err
		}
		var hc hunt.Context
		if err := decode(ctx, hs, o.ContextSHA, &hc); err != nil {
			return f, err
		}
		h := o.Hypothesis
		if n == 0 {
			f.Mechanism, f.Anchor, f.Invariant, f.Prediction = h.MechanismKey+": "+h.Mechanism, h.Anchor, h.Invariant, h.Prediction
			f.RootCause = fmt.Sprintf("%s:%d-%d (%s)", h.RootCause.Path, h.RootCause.Start, h.RootCause.End, h.RootCause.SHA)
			if _, err := b.add(hs, h.RootCause.SHA, "root-cause source"); err != nil {
				return f, err
			}
		}
		for _, cl := range validate.ClaimsFor(n, h) {
			f.Claims = append(f.Claims, Claim{ID: cl.ID, Text: cl.Text, Verifier: "not_reviewed"})
		}
		ev, err := b.add(hs, row.PayloadSHA, "candidate occurrence")
		if err != nil {
			return f, err
		}
		oc := Occurrence{Unit: row.UnitID, Entry: hc.Entry.Method.Class + "#" + hc.Entry.Method.Name + hc.Entry.Method.Descriptor, Static: o.Static.Execution, Evidence: ev}
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
				return f, err
			}
			oc.Resolution, oc.Search, oc.Model = axes.Resolution, axes.Search.State, axes.Model.State
			if _, err := b.add(hs, o.Static.ResponseSHA, "ariadne response"); err != nil {
				return f, err
			}
		}
		statics = append(statics, fmt.Sprintf("%s: %s/%s/%s", oc.Entry, oc.Static, oc.Resolution, oc.Search))
		f.Occurrences = append(f.Occurrences, oc)
		n++
	}
	f.Static = strings.Join(statics, "; ")
	ids := []string{}
	for id, e := range b.exps {
		if e.m.CandidateID == c.ID {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return b.exps[ids[i]].snap.Run.CreatedAt < b.exps[ids[j]].snap.Run.CreatedAt })
	f.Reproduction, f.Replay = "not_run", "not_run"
	for _, id := range ids {
		rep, err := b.reproduction(f, b.exps[id])
		if err != nil {
			return f, err
		}
		f.Experiments = append(f.Experiments, rep)
		f.Reproduction = rep.Outcome
	}
	var latest *validate.Summary
	for _, v := range b.reviews {
		if v.sum.Context.CandidateID != c.ID {
			continue
		}
		rv, err := b.review(v)
		if err != nil {
			return f, err
		}
		f.Reviews = append(f.Reviews, rv)
		if v.sum.Decision != nil {
			latest = v.sum
		}
	}
	if latest != nil {
		d := latest.Decision
		f.Label, f.Reason, f.Defect, f.Replay, f.Unresolved = d.Label, d.Reason, d.Defect, d.Replay, d.Unresolved
		status := map[string]Claim{}
		for _, a := range latest.Output.Claims {
			status[a.Claim] = Claim{Verifier: a.Status, Note: a.Observation}
		}
		for i, cl := range f.Claims {
			if s, ok := status[cl.ID]; ok {
				f.Claims[i].Verifier, f.Claims[i].Note = s.Verifier, s.Note
			}
		}
	} else {
		f.Label, f.Defect = "needs_validation", "candidate"
		f.Reason = "no independent validation decision is recorded for this candidate"
		f.Unresolved = append(f.Unresolved, "independent validation has not run")
		if len(f.Experiments) == 0 {
			f.Unresolved = append(f.Unresolved, "no controlled experiment has run")
		}
	}
	return f, nil
}

func (b *builder) reproduction(f Finding, e *expSource) (Reproduction, error) {
	ctx, s := b.ctx, e.s
	rep := Reproduction{ExperimentRun: e.snap.Run.ID, Outcome: "not_assessed", Cases: []Case{}, Harness: e.m.HarnessSHA, Spec: e.m.SpecSHA, Patch: e.m.PatchSHA, Gaps: []string{}}
	if len(e.snap.Reproductions) == 1 {
		row := e.snap.Reproductions[0]
		var a experiment.Assessment
		if err := decode(ctx, s, row.PayloadSHA, &a); err != nil {
			return rep, err
		}
		rep.Outcome, rep.Reason, rep.Gaps = a.Outcome, a.Reason, a.Gaps
		if _, err := b.add(s, row.PayloadSHA, "reproduction assessment"); err != nil {
			return rep, err
		}
		for _, cs := range a.Cases {
			var o experiment.Observation
			if err := decode(ctx, s, cs.ObservationSHA, &o); err != nil {
				return rep, err
			}
			ev, err := b.add(s, cs.ObservationSHA, "case observation")
			if err != nil {
				return rep, err
			}
			if _, err := b.add(s, o.SandboxSHA, "worker result"); err != nil {
				return rep, err
			}
			for _, l := range []*experiment.Listing{o.Listing, o.TmpListing} {
				if l == nil {
					continue
				}
				for _, en := range l.Entries {
					if en.Promoted {
						if _, err := b.add(s, en.SHA, "promoted worker file"); err != nil {
							return rep, err
						}
					}
				}
			}
			c := Case{ID: o.Case.ID, Role: o.Case.Role, Variant: o.Case.VariantName(), Args: o.Case.Args, Outcome: o.Outcome, Assertion: o.Assertion, Escapes: o.Escapes, Evidence: ev}
			if o.Harness != nil {
				c.Exception = o.Harness.Exception
			}
			rep.Cases = append(rep.Cases, c)
		}
	}
	// A self-contained reproducer: spec rewritten to sibling paths, harness,
	// patch and the commands that rerun it against the same preparation.
	dir := f.Evidence + "/reproducer/" + e.snap.Run.ID
	rep.Reproducer = dir
	raw, err := s.Get(ctx, e.m.SpecSHA)
	if err != nil {
		return rep, err
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		return rep, err
	}
	spec["harness"] = e.m.HarnessName
	harness, err := s.Get(ctx, e.m.HarnessSHA)
	if err != nil {
		return rep, err
	}
	if err := b.write(dir+"/"+e.m.HarnessName, harness); err != nil {
		return rep, err
	}
	if e.m.PatchSHA != "" {
		patch, err := s.Get(ctx, e.m.PatchSHA)
		if err != nil {
			return rep, err
		}
		if err := b.write(dir+"/correction.patch", patch); err != nil {
			return rep, err
		}
		if c, ok := spec["correction"].(map[string]any); ok {
			c["patch"] = "correction.patch"
		}
	}
	out, _ := json.MarshalIndent(spec, "", "  ")
	if err := b.write(dir+"/experiment.json", append(out, '\n')); err != nil {
		return rep, err
	}
	rep.Commands = []string{
		"tekmerion prepare -project PROJECT.json -checkout CHECKOUT -work PREPARED -ariadne ARIADNE   # must reproduce prepared manifest " + b.hm.PreparedSHA,
		"tekmerion experiment -hunt HUNT_STATE -work PREPARED -spec experiment.json -candidate " + f.ID + " -state NEW_EXPERIMENT",
		"tekmerion report -state NEW_EXPERIMENT",
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Reproducer for %s\n\nExperiment run `%s`; recorded reproduction **%s**.\n\nRun from this directory with the same prepared target (manifest `%s`) and a Hunt run containing the candidate:\n\n```sh\n%s\n```\n\nRecorded case outcomes:\n\n| Case | Role | Variant | Arguments | Outcome |\n|---|---|---|---|---|\n", f.ID, e.snap.Run.ID, rep.Outcome, b.hm.PreparedSHA, strings.Join(rep.Commands, "\n"))
	for _, c := range rep.Cases {
		fmt.Fprintf(&md, "| %s | %s | %s | %s | %s |\n", c.ID, c.Role, c.Variant, cell(strings.Join(c.Args, " ")), c.Outcome)
	}
	md.WriteString("\nThe sandbox needs bubblewrap, prlimit and a systemd user manager; without them the capability probe blocks the run.\n")
	if err := b.write(dir+"/README.md", []byte(md.String())); err != nil {
		return rep, err
	}
	return rep, nil
}

func (b *builder) review(v review) (Review, error) {
	s, sum := v.o.s, v.sum
	rv := Review{ValidationRun: v.o.snap.Run.ID, Mode: sum.Manifest.Mode, Label: "undecided", Verifier: "not_run", Replay: "not_run", Rules: validate.Rules, Controls: []string{}, Unresolved: []string{}}
	if sum.Replay != nil {
		rv.Replay = sum.Replay.Assessment.Outcome
		if _, err := b.add(s, sum.ReplaySHA, "fresh-worker replay"); err != nil {
			return rv, err
		}
	}
	if sum.Output != nil {
		rv.Verifier = sum.Output.Decision
		for _, c := range sum.Output.Controls {
			rv.Controls = append(rv.Controls, c.Text)
		}
		if _, err := b.add(s, sum.OutputSHA, "verifier output"); err != nil {
			return rv, err
		}
	}
	if _, err := b.add(s, sum.Manifest.ContextSHA, "verifier context"); err != nil {
		return rv, err
	}
	if d := sum.Decision; d != nil {
		rv.Label, rv.Reason, rv.Rules, rv.Unresolved = d.Label, d.Reason, d.Rules, d.Unresolved
		ev, err := b.add(s, sum.DecisionSHA, "decision")
		if err != nil {
			return rv, err
		}
		rv.Evidence = ev
	}
	return rv, nil
}

func (b *builder) summarize(r *Report) {
	sm := Summary{Candidates: len(r.Findings), Labels: map[string]int{"confirmed": 0, "needs_validation": 0, "rejected": 0}, Coverage: map[string]int{}, CoverageUnits: len(r.Coverage)}
	for _, f := range r.Findings {
		sm.Labels[f.Label]++
		if len(f.Reviews) == 0 {
			sm.Unvalidated++
		}
		if len(f.Experiments) == 0 {
			sm.Unexperimented++
		}
	}
	for _, u := range r.Coverage {
		sm.Coverage[u.Current]++
	}
	incomplete := []string{}
	for _, run := range r.Runs {
		if run.Status != "completed" {
			incomplete = append(incomplete, run.Kind+" "+run.RunID+" is "+run.Status)
		}
	}
	sm.Completion = "completed: every included run finished"
	if len(incomplete) > 0 {
		sm.Completion = "incomplete: " + strings.Join(incomplete, "; ")
	}
	r.Summary = sm

	costs := Costs{Runs: []Spend{}, Note: "Each run's own ledger; derived runs never charge their parent's spend again. Local compute, credit fees and taxes are excluded."}
	var settled, outstanding state.Money
	addSpend := func(kind, id string, bs *state.BudgetSnapshot) {
		if bs == nil {
			return
		}
		settled += bs.Settled
		outstanding += bs.Outstanding
		costs.Requests += bs.Requests
		costs.Runs = append(costs.Runs, Spend{RunID: id, Kind: kind, Limit: bs.Config.Limit.String(), Settled: bs.Settled.String(), Outstanding: bs.Outstanding.String(), Requests: bs.Requests, Tokens: bs.Tokens})
	}
	addSpend("recon", b.recon.Run.ID, b.recon.Budget)
	addSpend("hunt", b.hunt.snap.Run.ID, b.hunt.snap.Budget)
	for _, v := range b.reviews {
		addSpend("validation", v.o.snap.Run.ID, v.o.snap.Budget)
	}
	costs.Settled, costs.Outstanding = settled.String(), outstanding.String()
	r.Costs = costs

	if n := len(b.hm.DeferredUnits); n > 0 {
		r.Gaps = append(r.Gaps, fmt.Sprintf("%d planned coverage units were outside this Hunt wave", n))
	}
	if sm.Coverage["planned"] > 0 {
		r.Gaps = append(r.Gaps, fmt.Sprintf("%d coverage units are still planned", sm.Coverage["planned"]))
	}
	if sm.Coverage["deferred"] > 0 {
		r.Gaps = append(r.Gaps, fmt.Sprintf("%d coverage units are deferred", sm.Coverage["deferred"]))
	}
	if sm.Unexperimented > 0 {
		r.Gaps = append(r.Gaps, fmt.Sprintf("%d candidates have no controlled experiment", sm.Unexperimented))
	}
	if sm.Unvalidated > 0 {
		r.Gaps = append(r.Gaps, fmt.Sprintf("%d candidates have no independent validation", sm.Unvalidated))
	}
	r.Gaps = append(r.Gaps, "novelty lookup is not implemented; every finding's novelty is undetermined", "CVE-guided investigation packages are not implemented; every finding's origin is discovery")
	r.Limits = []string{
		"Labels are derived by versioned rules from independent axes; a confirmed label is bounded to the investigated property, scope and configuration.",
		"Novelty is undetermined; nothing here implies that a CVE identifier exists or has been assigned, and no severity is claimed.",
		"A missing confirmed finding does not certify the library's safety; it means no vulnerability was confirmed within the investigated scope.",
	}
	if r.Provenance == "control" {
		r.Limits = append(r.Limits, "Provenance is a control target: a deliberately vulnerable library used to qualify the workflow, not a real-world finding.")
	}
}
