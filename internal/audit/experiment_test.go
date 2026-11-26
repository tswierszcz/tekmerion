package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/state"
)

// An experiment ledger is reported from saved state alone, before any task runs.
func TestExperimentLedgerReportDispatch(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "run")
	s, err := state.Create(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile("../../testdata/experiments/extractor/experiment.json")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Put(ctx, spec, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := s.Put(ctx, []byte(`{}`), "application/json")
	m := experiment.Manifest{Schema: experiment.RunSchema, Mode: "checked-in-harness", ParentSHA: parent.SHA, ParentRunID: "run-parent", PreparedSHA: parent.SHA, CandidateID: "sha256:c", CandidateCanonical: "exact cause", OccurrenceSHAs: []string{}, SpecSHA: a.SHA, HarnessSHA: a.SHA, HarnessName: "ExtractHarness.java", Classpath: []string{"lib.jar"}, Cases: []experiment.CaseJob{{TaskID: "case-normal", CaseSHA: a.SHA}}}
	raw, _ := json.Marshal(m)
	ma, err := s.Put(ctx, raw, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, ma.SHA, []state.TaskInput{{ID: "case-normal", Stage: "experiment", InputSHA: a.SHA}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	report, err := Report(ctx, dir, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Tekmerion experiment ledger", "Paid model requests: **0**", "| case-normal | | not run |", "Not assessed yet."} {
		if !strings.Contains(string(report), want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
}
