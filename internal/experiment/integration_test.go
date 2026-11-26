package experiment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/sandbox"
	"github.com/tswierszcz/tekmerion/internal/state"
	"github.com/tswierszcz/tekmerion/internal/testsupport"
)

func huntWithCandidate(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	if err := sandbox.Available(); err != nil {
		t.Skip(err)
	}
	return testsupport.HuntWithCandidate(t)
}

func TestRealExperimentReproducesControlCandidate(t *testing.T) {
	ctx, work, huntDir, candidate := huntWithCandidate(t)
	spec := "../../testdata/experiments/extractor/experiment.json"
	dir := filepath.Join(t.TempDir(), "experiment")
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: "sha256:unknown", State: dir}); err == nil {
		t.Fatal("unknown candidate accepted")
	}
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: candidate, State: dir}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, dir); err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, _, _, err := load(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Reproductions) != 1 || snap.Reproductions[0].Outcome != "reproduced" || snap.Reproductions[0].CandidateID != candidate {
		if sha, ok := completed(snap, "capabilities"); ok {
			var c sandbox.Capabilities
			decode(ctx, s, sha, &c)
			for _, v := range c.Checks {
				if !v.OK {
					t.Logf("capability check failed: %+v", v)
				}
			}
			if c.Probe != nil {
				t.Logf("probe stdout %s stderr %s", c.Probe.Stdout, c.Probe.Stderr)
			}
		}
		t.Fatalf("unexpected run: %s %+v", snap.Run.Status, snap.Reproductions)
	}
	obs := map[string]Observation{}
	for _, task := range []string{"case-normal", "case-traversal", "case-corrected-traversal"} {
		sha, _ := completed(snap, task)
		var o Observation
		if err := decode(ctx, s, sha, &o); err != nil {
			t.Fatal(err)
		}
		obs[task] = o
	}
	if o := obs["case-traversal"]; o.Outcome != "property_violated" || strings.Join(o.Escapes, ",") != "/case/escaped.txt" || o.Harness == nil || o.Harness.Exception != "" {
		t.Fatalf("traversal case: %+v", o)
	}
	if o := obs["case-normal"]; o.Outcome != "property_held" || len(o.Escapes) != 0 || len(o.Listing.Entries) != 2 || o.Listing.Entries[1].Path != "jail/entry.txt" || !o.Listing.Entries[1].Promoted {
		t.Fatalf("normal case: %+v", o)
	}
	if o := obs["case-corrected-traversal"]; o.Outcome != "target_exception" || o.Assertion != "held" || len(o.Escapes) != 0 || o.Harness == nil || !strings.Contains(o.Harness.Exception, "entry outside the target directory") {
		t.Fatalf("corrected control case: %+v", o)
	}
	var rec VariantRecord
	sha, _ := completed(snap, "correction")
	if err := decode(ctx, s, sha, &rec); err != nil || rec.Variant == nil || len(rec.Variant.Changed) != 1 || rec.Sources["testdata/research/lib/fx/research/Extractor.java"] != rec.Variant.Changed[0].After {
		t.Fatalf("variant record: %+v %v", rec, err)
	}
	report, err := Report(ctx, s, snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Established: **true**", "Reproduction: **reproduced**", "Defect: **candidate**", "## Corrected variant", "operator-supplied patch", "| traversal | candidate | original | **property_violated** |", "| corrected-traversal | control | corrected | **target_exception** |"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	again, err := Report(ctx, s, snap)
	if err != nil || again != report {
		t.Fatal("report regeneration is not deterministic")
	}
	s.Close()
	if err := Resume(ctx, dir); err != nil {
		t.Fatal("resume of a completed run must be a no-op: ", err)
	}

	// A patch that does not apply is recorded; the control cannot hold, so
	// the assessment is inconclusive rather than reproduced.
	bad := t.TempDir()
	raw, _ := os.ReadFile(spec)
	var sp map[string]any
	json.Unmarshal(raw, &sp)
	sp["harness"], _ = filepath.Abs("../../testdata/experiments/extractor/ExtractHarness.java")
	sp["correction"] = map[string]any{"patch": "bad.patch", "description": "does not apply"}
	raw, _ = json.Marshal(sp)
	os.WriteFile(filepath.Join(bad, "spec.json"), raw, 0600)
	os.WriteFile(filepath.Join(bad, "bad.patch"), []byte("--- a/missing.java\n+++ b/missing.java\n@@ -1 +1 @@\n-x\n+y\n"), 0600)
	dir3 := filepath.Join(bad, "run")
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: filepath.Join(bad, "spec.json"), Candidate: candidate, State: dir3}); err != nil {
		t.Fatal(err)
	}
	if err := Resume(ctx, dir3); err != nil {
		t.Fatal(err)
	}
	s3, err := state.Open(ctx, dir3)
	if err != nil {
		t.Fatal(err)
	}
	snap3, err := s3.Snapshot(ctx)
	s3.Close()
	if err != nil || len(snap3.Reproductions) != 1 || snap3.Reproductions[0].Outcome != "inconclusive" || !strings.Contains(snap3.Reproductions[0].Reason, "corrected-traversal=variant_unavailable") {
		t.Fatalf("unappliable patch: %+v %v", snap3.Reproductions, err)
	}

	// A modified target invalidates reproduction instead of producing evidence.
	dir2 := filepath.Join(t.TempDir(), "tampered")
	if err := Start(ctx, Options{Hunt: huntDir, Work: work, Spec: spec, Candidate: candidate, State: dir2}); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(work, "out", "lib.jar")
	os.Chmod(filepath.Dir(jar), 0700)
	os.Chmod(jar, 0600)
	f, err := os.OpenFile(jar, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("tamper"))
	f.Close()
	if err := Resume(ctx, dir2); err != nil {
		t.Fatal(err)
	}
	s2, err := state.Open(ctx, dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	snap2, err := s2.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap2.Reproductions) != 1 || snap2.Reproductions[0].Outcome != "inconclusive" || !strings.Contains(snap2.Reproductions[0].Reason, "prepared target did not match") {
		t.Fatalf("tampered target: %+v", snap2.Reproductions)
	}
}
