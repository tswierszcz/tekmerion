package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDecisionAtomicAndImmutable(t *testing.T) {
	ctx := context.Background()
	s, err := Create(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Put(ctx, []byte(`{"decision":"test"}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Start(ctx, a.SHA, []TaskInput{{ID: "replay", Stage: "experiment", InputSHA: a.SHA}, {ID: "decide", Stage: "decision", InputSHA: a.SHA}})
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{TaskID: "decide", CandidateID: "sha256:c", Label: "confirmed", Verifier: "supported", Rules: "rules-1", Reason: "test", PayloadSHA: a.SHA}
	wrong, err := s.Claim(ctx, run.ID, "replay", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bad := d
	bad.TaskID = "replay"
	if err := s.CommitDecision(ctx, *wrong, a.SHA, bad); err == nil {
		t.Fatal("decision accepted from a non-decision task")
	}
	if err := s.Finish(ctx, *wrong, "completed", a.SHA, ""); err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, run.ID, "decide", "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Decision){func(v *Decision) { v.Label = "zero-day" }, func(v *Decision) { v.Verifier = "maybe" }, func(v *Decision) { v.Rules = "" }} {
		v := d
		change(&v)
		if err := s.CommitDecision(ctx, *claim, a.SHA, v); err == nil {
			t.Fatalf("invalid decision accepted: %+v", v)
		}
	}
	if err := s.CommitDecision(ctx, *claim, a.SHA, d); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitDecision(ctx, *claim, a.SHA, d); err != nil {
		t.Fatal("identical redelivery must be a no-op: ", err)
	}
	other := d
	other.Label = "rejected"
	if err := s.CommitDecision(ctx, *claim, a.SHA, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("contradictory redelivery: %v", err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Decisions) != 1 || snap.Decisions[0] != d {
		t.Fatalf("snapshot: %s %+v", snap.Run.Status, snap.Decisions)
	}
	if _, err := s.db.Exec("DELETE FROM decisions"); err == nil {
		t.Fatal("decision history is mutable")
	}
}
