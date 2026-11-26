package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Create(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func put(t *testing.T, s *Store, raw string) string {
	t.Helper()
	a, err := s.Put(context.Background(), []byte(raw), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	return a.SHA
}
func start(t *testing.T, s *Store) *Run {
	t.Helper()
	sha := put(t, s, `{"test":true}`)
	run, err := s.Start(context.Background(), sha, []TaskInput{{ID: "one", Stage: "fixture", InputSHA: sha}})
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestStartIsAtomicAndIdentityIsImmutable(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	sha := put(t, s, `{}`)
	inputs := []TaskInput{{ID: "one", Stage: "fixture", InputSHA: sha}, {ID: "one", Stage: "fixture", InputSHA: sha}}
	if _, err := s.Start(ctx, sha, inputs); err == nil {
		t.Fatal("duplicate task accepted")
	}
	if _, err := s.Snapshot(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("partially committed run: %v", err)
	}
	r, err := s.Start(ctx, sha, inputs[:1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, sha, inputs[:1]); err == nil {
		t.Fatal("second run in same directory accepted")
	}
	if _, err := s.db.Exec("UPDATE runs SET manifest_sha=? WHERE id=?", sha, r.ID); err == nil {
		t.Fatal("run identity can be overwritten")
	}
	if _, err := s.db.Exec("UPDATE tasks SET input_sha=? WHERE run_id=?", sha, r.ID); err == nil {
		t.Fatal("task input can be overwritten")
	}
}

func TestCrashRestartLeaseAndDuplicateDelivery(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	clock := time.Now()
	s.now = func() time.Time { return clock }
	run := start(t, s)
	first, err := s.Claim(ctx, run.ID, "one", "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Attempts) != 1 || before.Attempts[0].Outcome != "running" {
		t.Fatalf("attempt not persisted: %+v", before)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	recovered.now = func() time.Time { return clock }
	if _, err := recovered.Claim(ctx, run.ID, "one", "worker-b", time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatalf("live lease stolen: %v", err)
	}
	clock = clock.Add(time.Minute)
	if err := recovered.Finish(ctx, *first, "completed", "", ""); !errors.Is(err, ErrLease) {
		t.Fatalf("expired result accepted: %v", err)
	}
	second, err := recovered.Claim(ctx, run.ID, "one", "worker-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.Token == first.Token || second.Number != 2 {
		t.Fatal("retry did not receive new identity")
	}
	if err := recovered.Finish(ctx, *first, "completed", "", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("old worker overwrote retry: %v", err)
	}
	result := put(t, recovered, `{"result":"ok"}`)
	if err := recovered.Finish(ctx, *second, "completed", result, ""); err != nil {
		t.Fatal(err)
	}
	snap, err := recovered.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snap)
	if snap.Run.Status != "completed" || len(snap.Attempts) != 2 || snap.Attempts[0].Outcome != "interrupted" || snap.Attempts[1].Outcome != "completed" {
		t.Fatalf("bad recovered state: %+v", snap)
	}
	clock = clock.Add(time.Hour)
	if err := recovered.Finish(ctx, *second, "completed", result, ""); err != nil {
		t.Fatalf("duplicate rejected: %v", err)
	}
	after, err := recovered.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repeated, _ := json.Marshal(after)
	if string(raw) != string(repeated) {
		t.Fatal("duplicate settlement changed saved state")
	}
	if err := recovered.Finish(ctx, *second, "failed", result, "different"); !errors.Is(err, ErrConflict) {
		t.Fatalf("contradictory result accepted: %v", err)
	}
	if _, err := recovered.Claim(ctx, run.ID, "one", "worker-c", time.Minute); !errors.Is(err, ErrTerminal) {
		t.Fatalf("completed task replayed: %v", err)
	}
	for _, query := range []string{"UPDATE attempts SET worker='overwrite'", "DELETE FROM attempts", "UPDATE attempt_results SET diagnostic='overwrite'", "DELETE FROM attempt_results"} {
		if _, err := recovered.db.Exec(query); err == nil {
			t.Fatalf("history mutation accepted: %s", query)
		}
	}
}

func TestTwoIndependentWorkersClaimOneTask(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	run := start(t, s)
	other, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	gate := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i, db := range []*Store{s, other} {
		group.Add(1)
		go func(worker int, db *Store) {
			defer group.Done()
			<-gate
			_, err := db.Claim(ctx, run.ID, "one", string(rune('a'+worker)), time.Minute)
			results <- err
		}(i, db)
	}
	close(gate)
	group.Wait()
	close(results)
	won, busy := 0, 0
	for err := range results {
		if err == nil {
			won++
		} else if errors.Is(err, ErrBusy) {
			busy++
		} else {
			t.Fatal(err)
		}
	}
	if won != 1 || busy != 1 {
		t.Fatalf("won=%d busy=%d", won, busy)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Attempts) != 1 {
		t.Fatal("more than one attempt admitted")
	}
}

func TestRenewAndGracefulInterruption(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	clock := time.Now()
	s.now = func() time.Time { return clock }
	run := start(t, s)
	claim, err := s.Claim(ctx, run.ID, "one", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(30 * time.Second)
	if err := s.Renew(ctx, *claim, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	if _, err := s.Claim(ctx, run.ID, "one", "other", time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatalf("renewed lease lost: %v", err)
	}
	if err := s.Finish(ctx, *claim, "interrupted", "", "cancelled locally"); err != nil {
		t.Fatal(err)
	}
	next, err := s.Claim(ctx, run.ID, "one", "other", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if next.Number != 2 {
		t.Fatal("lost interrupted attempt")
	}
	if err := s.Renew(ctx, *claim, time.Hour); !errors.Is(err, ErrLease) {
		t.Fatal("old worker renewed new attempt")
	}
	if err := s.Finish(ctx, *next, "failed", "", "deterministic failure"); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "failed" {
		t.Fatal("failed run marked complete")
	}
}

func TestArtifactsFailClosedOnTampering(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	sha := put(t, s, `{"original":1}`)
	if other := put(t, s, `{"original":1}`); sha != other {
		t.Fatal("identical bytes have different identities")
	}
	path := filepath.Join(s.dir, "artifacts", sha[7:])
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"original":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, sha); err == nil {
		t.Fatal("tampered bytes accepted")
	}
	if _, err := s.Put(ctx, []byte(`{"original":1}`), "application/json"); err == nil {
		t.Fatal("corrupt evidence silently replaced")
	}
	if _, err := s.Get(ctx, "../state.sqlite"); err == nil {
		t.Fatal("non-hash path accepted")
	}
}

func TestUnsupportedSchemaAndMissingState(t *testing.T) {
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Open(ctx, missing); err == nil {
		t.Fatal("missing state silently initialized")
	}
	s, dir := newStore(t)
	if _, err := s.db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if db, err := Open(ctx, dir); err == nil {
		db.Close()
		t.Fatal("future schema accepted")
	}
}

func TestFailedResultCommitLeavesLiveAttemptIntact(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	run := start(t, s)
	claim, err := s.Claim(ctx, run.ID, "one", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	missing := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := s.Finish(ctx, *claim, "completed", missing, ""); err == nil {
		t.Fatal("result referencing unsaved artifact accepted")
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "running" || snap.Tasks[0].Status != "running" || snap.Attempts[0].Outcome != "running" {
		t.Fatalf("partial result commit: %+v", snap)
	}
	sha := put(t, s, `{"result":"saved"}`)
	if err := s.Finish(ctx, *claim, "completed", sha, ""); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageProjectionAtomicAndIdempotent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	sha := put(t, s, `{"context":1}`)
	run, err := s.Start(ctx, sha, []TaskInput{{ID: "coverage", Stage: "coverage", InputSHA: sha}})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, run.ID, "coverage", "projector", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `["repo","class#method()V","boundary","subsystem","property"]`
	seed := CoverageSeed{ID: digest([]byte(canonical)), Canonical: canonical, SourceIdentity: digest([]byte("source")), PayloadSHA: digest([]byte("not saved")), Status: "planned"}
	if err := s.CommitCoverage(ctx, *claim, sha, []CoverageSeed{seed}); err == nil {
		t.Fatal("coverage accepted missing payload")
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Coverage) != 0 || snap.Attempts[0].Outcome != "running" {
		t.Fatal("partial coverage/attempt commit")
	}
	seed.PayloadSHA = sha
	if err := s.CommitCoverage(ctx, *claim, sha, []CoverageSeed{seed, seed}); err == nil {
		t.Fatal("duplicate canonical identity merged")
	}
	if err := s.CommitCoverage(ctx, *claim, sha, []CoverageSeed{seed}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Run.Status != "completed" || len(before.Coverage) != 1 {
		t.Fatal("coverage task not atomically completed")
	}
	if err := s.CommitCoverage(ctx, *claim, sha, []CoverageSeed{seed}); err != nil {
		t.Fatal(err)
	}
	changed := seed
	changed.Status = "checked"
	if err := s.CommitCoverage(ctx, *claim, sha, []CoverageSeed{changed}); err == nil {
		t.Fatal("Recon promoted unchecked coverage")
	}
	changed = seed
	changed.Reason = "different evidence"
	if err := s.CommitCoverage(ctx, *claim, sha, []CoverageSeed{changed}); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting projection silently accepted")
	}
	for _, stmt := range []string{"DELETE FROM coverage_units", "UPDATE coverage_units SET status='blocked'", "DELETE FROM coverage_batches"} {
		if _, err := s.db.Exec(stmt); err == nil {
			t.Fatal("initial coverage history mutable")
		}
	}
}
