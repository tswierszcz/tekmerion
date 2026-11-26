package state

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestHuntAtomicHistoryAndExactDedup(t *testing.T) {
	ctx := context.Background()
	s, err := Create(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	artifact, err := s.Put(ctx, []byte(`{"evidence":"test"}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Start(ctx, artifact.SHA, []TaskInput{{ID: "coverage", Stage: "coverage", InputSHA: artifact.SHA}, {ID: "triage-1", Stage: "triage", InputSHA: artifact.SHA}, {ID: "triage-2", Stage: "triage", InputSHA: artifact.SHA}})
	if err != nil {
		t.Fatal(err)
	}
	source := digest([]byte("source"))
	seeds := []CoverageSeed{}
	for _, key := range []string{"one", "two"} {
		seeds = append(seeds, CoverageSeed{ID: digest([]byte(key)), Canonical: key, SourceIdentity: source, PayloadSHA: artifact.SHA, Status: "planned"})
	}
	claim, err := s.Claim(ctx, run.ID, "coverage", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitCoverage(ctx, *claim, artifact.SHA, seeds); err != nil {
		t.Fatal(err)
	}
	canonical := "same exact source mechanism"
	id := digest([]byte(canonical))
	var first Claim
	var prior HuntCommit
	for i, task := range []string{"triage-1", "triage-2"} {
		claim, err := s.Claim(ctx, run.ID, task, "test", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		commit := HuntCommit{Candidates: []Candidate{{ID: id, Canonical: canonical, SourceIdentity: source, PayloadSHA: artifact.SHA}}, Occurrences: []CandidateOccurrence{{CandidateID: id, UnitID: seeds[i].ID, TaskID: task, PayloadSHA: artifact.SHA}}, Event: CoverageEvent{UnitID: seeds[i].ID, TaskID: task, Status: "candidate", Reason: "bounded source hypothesis", PayloadSHA: artifact.SHA}}
		if i == 0 {
			bad := commit
			bad.Event.PayloadSHA = digest([]byte("not archived"))
			if err := s.CommitHunt(ctx, *claim, artifact.SHA, bad); err == nil {
				t.Fatal("missing artifact accepted")
			}
			snap, err := s.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(snap.Candidates) != 0 || len(snap.CoverageHistory) != 0 || len(snap.Occurrences) != 0 {
				t.Fatal("failed transaction left candidate history")
			}
			bad = commit
			bad.Candidates = append([]Candidate{}, commit.Candidates...)
			bad.Candidates[0].SourceIdentity = digest([]byte("stale source"))
			if err := s.CommitHunt(ctx, *claim, artifact.SHA, bad); err == nil {
				t.Fatal("stale source accepted")
			}
			first = *claim
			prior = commit
		}
		if err := s.CommitHunt(ctx, *claim, artifact.SHA, commit); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Candidates) != 1 || len(snap.Occurrences) != 2 || len(snap.CoverageHistory) != 2 {
		t.Fatalf("lost exact dedup/paths: %+v", snap)
	}
	for _, v := range snap.Coverage {
		if v.Status != "planned" {
			t.Fatal("initial coverage overwritten")
		}
	}
	before, _ := json.Marshal(snap)
	if err := s.CommitHunt(ctx, first, artifact.SHA, prior); err != nil {
		t.Fatal(err)
	}
	prior.Event.Reason = "contradiction"
	if err := s.CommitHunt(ctx, first, artifact.SHA, prior); !errors.Is(err, ErrConflict) {
		t.Fatalf("contradictory redelivery: %v", err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(after)
	if string(raw) != string(before) {
		t.Fatal("idempotent delivery changed snapshot")
	}
	for _, table := range []string{"candidates", "candidate_occurrences", "coverage_events", "hunt_batches"} {
		if _, err := s.db.Exec("DELETE FROM " + table); err == nil {
			t.Fatal("mutable history", table)
		}
	}
}

func TestVersionFourMigrationPreservesCoverage(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "legacy")
	s, err := Create(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Put(ctx, []byte("legacy evidence"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Start(ctx, a.SHA, []TaskInput{{ID: "coverage", Stage: "coverage", InputSHA: a.SHA}})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, run.ID, "coverage", "legacy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	seeds := []CoverageSeed{{ID: digest([]byte("legacy unit")), Canonical: "legacy unit", SourceIdentity: digest([]byte("source")), PayloadSHA: a.SHA, Status: "planned"}}
	if err := s.CommitCoverage(ctx, *claim, a.SHA, seeds); err != nil {
		t.Fatal(err)
	}
	// Remove only empty v5/v6 additions to recreate the previous persisted schema.
	for _, table := range []string{"decisions", "reproductions", "candidate_occurrences", "coverage_events", "candidates", "hunt_batches"} {
		if _, err := s.db.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("PRAGMA user_version=4"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	migrated, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	snap, err := migrated.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Schema != SchemaVersion || snap.Run.ID != run.ID || snap.Run.Status != "completed" || len(snap.Coverage) != 1 || snap.Coverage[0].ID != seeds[0].ID || len(snap.Attempts) != 1 {
		t.Fatal("migration changed existing history")
	}
	if err := migrated.Verify(ctx, snap); err != nil {
		t.Fatal(err)
	}
}
