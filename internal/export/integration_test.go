package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/sandbox"
	"github.com/tswierszcz/tekmerion/internal/testsupport"
	"github.com/tswierszcz/tekmerion/internal/validate"
)

func supported(c validate.Context) []byte {
	o := validate.Output{Schema: validate.ResultSchema, InputIdentity: c.Identity, Decision: "supported", Reason: "Synthetic test verdict; not a security review", Controls: []validate.Control{{Text: "synthetic: no containment before the write", Citations: []recon.Citation{c.RootCause}}}, Unresolved: []string{}, Gaps: c.Gaps}
	for _, cl := range c.Claims {
		o.Claims = append(o.Claims, validate.Assessment{Claim: cl.ID, Status: "supported", Observation: "synthetic observation", Citations: []recon.Citation{c.RootCause}, Evidence: []string{"traversal"}})
	}
	raw, _ := json.Marshal(o)
	return raw
}

func readReport(t *testing.T, dir string) (Report, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r, raw
}

func TestRealExportChain(t *testing.T) {
	if err := sandbox.Available(); err != nil {
		t.Skip(err)
	}
	ctx, work, huntDir, candidate := testsupport.HuntWithCandidate(t)
	root := t.TempDir()

	// Hunt only: every candidate needs validation and names what is missing.
	only := filepath.Join(root, "hunt-only")
	if err := Export(ctx, Options{Hunt: huntDir, Out: only, Provenance: "control"}); err != nil {
		t.Fatal(err)
	}
	r, _ := readReport(t, only)
	if r.Summary.Candidates == 0 || r.Summary.Labels["needs_validation"] != r.Summary.Candidates || r.Summary.Unvalidated != r.Summary.Candidates || len(r.Coverage) == 0 {
		t.Fatalf("hunt-only summary: %+v", r.Summary)
	}

	exp := filepath.Join(root, "experiment")
	spec := filepath.Join(testsupport.Root(), "testdata/experiments/extractor/experiment.json")
	if err := experiment.Start(ctx, experiment.Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: candidate, State: exp}); err != nil {
		t.Fatal(err)
	}
	if err := experiment.Resume(ctx, exp); err != nil {
		t.Fatal(err)
	}
	c, _, err := validate.BuildContext(ctx, exp)
	if err != nil {
		t.Fatal(err)
	}
	val := filepath.Join(root, "validation")
	if err := validate.Start(ctx, validate.Options{Experiment: exp, State: val, Replay: supported(c)}); err != nil {
		t.Fatal(err)
	}
	if err := validate.Resume(ctx, val, nil); err != nil {
		t.Fatal(err)
	}

	// The validation archives its experiment, so the experiment directory is
	// optional; supplying both must not double count the experiment.
	out := filepath.Join(root, "export")
	if err := Export(ctx, Options{Hunt: huntDir, Runs: []string{val, exp}, Out: out, Provenance: "control", GeneratedAt: "2026-11-26T12:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	r, raw := readReport(t, out)
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == candidate {
			f = &r.Findings[i]
		}
	}
	if f == nil || f.Label != "confirmed" || f.Reproduction != "reproduced" || f.Replay != "reproduced" || f.Novelty != "undetermined" || len(f.Experiments) != 1 || len(f.Reviews) != 1 {
		t.Fatalf("finding: %+v", f)
	}
	if r.Summary.Labels["confirmed"] != 1 || r.Summary.Labels["confirmed"]+r.Summary.Labels["needs_validation"]+r.Summary.Labels["rejected"] != r.Summary.Candidates {
		t.Fatalf("summary double counts: %+v", r.Summary)
	}
	kinds := map[string]int{}
	for _, run := range r.Runs {
		kinds[run.Kind]++
	}
	if kinds["recon"] != 1 || kinds["hunt"] != 1 || kinds["experiment"] != 1 || kinds["validation"] != 1 {
		t.Fatalf("runs: %+v", r.Runs)
	}
	for _, claim := range f.Claims {
		if claim.Verifier != "supported" {
			t.Fatalf("claim not carried from the verifier: %+v", claim)
		}
	}
	rep := f.Experiments[0]
	for _, name := range []string{"README.md", "experiment.json", "ExtractHarness.java", "correction.patch"} {
		if _, err := os.Stat(filepath.Join(out, rep.Reproducer, name)); err != nil {
			t.Fatalf("reproducer lacks %s", name)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, "report.md"))
	for _, want := range []string{"provenance **control**", "confirmed **1**", "deliberately vulnerable", "novelty **undetermined**"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report.md lacks %q", want)
		}
	}
	if err := Verify(out); err != nil {
		t.Fatal(err)
	}

	// Deterministic for the same saved state and metadata.
	again := filepath.Join(root, "again")
	if err := Export(ctx, Options{Hunt: huntDir, Runs: []string{exp, val}, Out: again, Provenance: "control", GeneratedAt: "2026-11-26T12:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if _, raw2 := readReport(t, again); string(raw2) != string(raw) {
		t.Fatal("export is not deterministic")
	}

	// Tampering with exported evidence or the Markdown is detected.
	idx, _ := os.ReadFile(filepath.Join(out, "evidence/index.json"))
	var index Index
	json.Unmarshal(idx, &index)
	victim := filepath.Join(out, index.Artifacts[0].Path)
	os.WriteFile(victim, []byte("tampered"), 0o644)
	if Verify(out) == nil {
		t.Fatal("tampered artifact accepted")
	}
	os.WriteFile(filepath.Join(again, "report.md"), append(md, []byte("\nextra claim\n")...), 0o644)
	if Verify(again) == nil {
		t.Fatal("edited report.md accepted")
	}

	// Refusals leave no partial output.
	for name, o := range map[string]Options{
		"existing output": {Hunt: huntDir, Out: out, Provenance: "control"},
		"no provenance":   {Hunt: huntDir, Out: filepath.Join(root, "x1")},
		"wrong parent":    {Hunt: exp, Out: filepath.Join(root, "x2"), Provenance: "control"},
		"foreign run":     {Hunt: huntDir, Runs: []string{huntDir}, Out: filepath.Join(root, "x3"), Provenance: "control"},
	} {
		if err := Export(ctx, o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".partial-") {
			t.Fatalf("partial export left behind: %s", e.Name())
		}
	}
}
