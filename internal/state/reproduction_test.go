package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReproductionAtomicAndImmutable(t *testing.T) {
	ctx := context.Background()
	s, err := Create(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Put(ctx, []byte(`{"assessment":"test"}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Start(ctx, a.SHA, []TaskInput{{ID: "case-x", Stage: "experiment", InputSHA: a.SHA}, {ID: "assess", Stage: "assessment", InputSHA: a.SHA}})
	if err != nil {
		t.Fatal(err)
	}
	r := Reproduction{TaskID: "assess", CandidateID: "sha256:c", Outcome: "reproduced", Reason: "test", PayloadSHA: a.SHA}
	wrong, err := s.Claim(ctx, run.ID, "case-x", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bad := r
	bad.TaskID = "case-x"
	if err := s.CommitReproduction(ctx, *wrong, a.SHA, bad); err == nil {
		t.Fatal("reproduction accepted from a non-assessment task")
	}
	if err := s.Finish(ctx, *wrong, "completed", a.SHA, ""); err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, run.ID, "assess", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	invalid := r
	invalid.Outcome = "confirmed"
	if err := s.CommitReproduction(ctx, *claim, a.SHA, invalid); err == nil {
		t.Fatal("unknown outcome accepted")
	}
	if err := s.CommitReproduction(ctx, *claim, a.SHA, r); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitReproduction(ctx, *claim, a.SHA, r); err != nil {
		t.Fatal("identical redelivery must be a no-op: ", err)
	}
	other := r
	other.Outcome = "inconclusive"
	if err := s.CommitReproduction(ctx, *claim, a.SHA, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("contradictory redelivery: %v", err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Reproductions) != 1 || snap.Reproductions[0] != r {
		t.Fatalf("snapshot: %s %+v", snap.Run.Status, snap.Reproductions)
	}
	if _, err := s.db.Exec("UPDATE reproductions SET outcome='not_reproduced'"); err == nil {
		t.Fatal("reproduction history is mutable")
	}
}
