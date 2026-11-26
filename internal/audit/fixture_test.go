package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/state"
)

const fixtureContract = "../../contracts/ariadne/v1"

func TestDurableFixtureResumeAndReport(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "run")
	if err := StartFixture(ctx, dir, fixtureContract); err != nil {
		t.Fatal(err)
	}
	snap, err := Status(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Tasks) != 9 || len(snap.Attempts) != 0 {
		t.Fatalf("unexpected initial queue: %+v", snap)
	}
	s, err := state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A hard stop leaves an open attempt; a successor must retain it and create
	// a new attempt rather than overwriting it. No wall-clock sleeps required.
	abandoned, err := s.Claim(ctx, snap.Run.ID, snap.Tasks[0].ID, "killed-worker", time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ResumeFixture(ctx, dir); err != nil {
		t.Fatal(err)
	}
	snap, err = Status(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Attempts) != 10 {
		t.Fatalf("failed recovery: %+v", snap)
	}
	if snap.Attempts[0].Token != abandoned.Token || snap.Attempts[0].Outcome != "interrupted" {
		t.Fatal("lost original attempt")
	}
	for _, task := range snap.Tasks {
		if task.Status != "completed" {
			t.Fatalf("unfinished task %+v", task)
		}
	}
	jsonReport, err := Report(ctx, dir, "json")
	if err != nil {
		t.Fatal(err)
	}
	md, err := Report(ctx, dir, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(md, []byte("Provenance: **fixture**")) || !bytes.Contains(md, []byte("interrupted")) {
		t.Fatalf("lost fixture scope or interruption: %s", md)
	}
	if err := ResumeFixture(ctx, dir); err != nil {
		t.Fatal(err)
	}
	repeated, err := Report(ctx, dir, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonReport, repeated) {
		t.Fatal("resume reran completed work or changed report")
	}
	repeatedMD, err := Report(ctx, dir, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(md, repeatedMD) {
		t.Fatal("non-deterministic markdown report")
	}
	s, err = state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, attempt := range snap.Attempts {
		if attempt.Outcome != "completed" {
			continue
		}
		raw, err := s.Get(ctx, attempt.ResultSHA)
		if err != nil {
			t.Fatal(err)
		}
		var evidence Evidence
		if err := json.Unmarshal(raw, &evidence); err != nil {
			t.Fatal(err)
		}
		if evidence.Provenance != "fixture" || evidence.ValidationScope != "bundle" || evidence.Outcome != "result" {
			t.Fatalf("unvalidated evidence accepted: %+v", evidence)
		}
		if _, err := s.Get(ctx, evidence.ResponseSHA); err != nil {
			t.Fatal(err)
		}
	}
	// A changed saved artifact must block report generation.
	path := filepath.Join(dir, "artifacts", snap.Run.ManifestSHA[7:])
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Report(ctx, dir, "markdown"); err == nil {
		t.Fatal("report accepted corrupted artifact")
	}
}

func TestResumeRespectsLiveOwnerAndCancelledContext(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "run")
	if err := StartFixture(ctx, dir, fixtureContract); err != nil {
		t.Fatal(err)
	}
	before, err := Status(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if err := ResumeFixture(stopped, dir); err == nil {
		t.Fatal("cancelled resume succeeded")
	}
	after, err := Status(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Attempts) != 0 {
		t.Fatal("cancelled worker admitted new work")
	}
	s, err := state.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	claim, err := s.Claim(ctx, before.Run.ID, before.Tasks[0].ID, "active-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResumeFixture(ctx, dir); err == nil {
		t.Fatal("resume stole a live lease")
	}
	if err := s.Finish(ctx, *claim, "interrupted", "", "manual interruption"); err != nil {
		t.Fatal(err)
	}
	if err := ResumeFixture(ctx, dir); err != nil {
		t.Fatal(err)
	}
}

func TestResumeRejectsChangedContractPinBeforeClaim(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	copied := filepath.Join(root, "contract", "v1")
	if err := os.CopyFS(copied, os.DirFS(fixtureContract)); err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join(fixtureContract, "..", "PIN.json"))
	if err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(root, "contract", "PIN.json")
	if err := os.WriteFile(pinPath, pin, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "state")
	if err := StartFixture(ctx, dir, copied); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, append(pin, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ResumeFixture(ctx, dir); err == nil {
		t.Fatal("changed contract pin silently reused")
	}
	snap, err := Status(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Attempts) != 0 {
		t.Fatal("work claimed before verifying saved pin")
	}
	// Reports need only the stored state, even when the original package moves.
	if err := os.Rename(filepath.Join(root, "contract"), filepath.Join(root, "moved-contract")); err != nil {
		t.Fatal(err)
	}
	if _, err := Report(ctx, dir, "markdown"); err != nil {
		t.Fatalf("offline report requires original fixture package: %v", err)
	}
}

func TestFixtureBudgetSurvivesResumeAndReport(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "run")
	config, err := state.ParseBudget([]byte(`{"schema_version":"tekmerion-budget-1","currency":"USD","limit_usd":"10","validation_reserve_usd":"2","reporting_reserve_usd":"1","max_requests":100,"max_tokens":100000,"wall_time_seconds":3600}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := StartFixtureBudget(ctx, dir, fixtureContract, &config); err != nil {
		t.Fatal(err)
	}
	if err := ResumeFixture(ctx, dir); err != nil {
		t.Fatal(err)
	}
	snap, err := Status(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Budget == nil || snap.Budget.Config != config || snap.Budget.Available != 7*state.Dollar || snap.Budget.Requests != 0 || snap.Budget.Settled != 0 {
		t.Fatalf("local fixture consumed model budget: %+v", snap.Budget)
	}
	jsonBefore, err := Report(ctx, dir, "json")
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := Report(ctx, dir, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(markdown, []byte("## Budget (USD)")) || !bytes.Contains(markdown, []byte("available: 7.000000000")) {
		t.Fatalf("missing budget summary: %s", markdown)
	}
	if err := ResumeFixture(ctx, dir); err != nil {
		t.Fatal(err)
	}
	after, err := Report(ctx, dir, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonBefore, after) {
		t.Fatal("resume changed budget")
	}
}
