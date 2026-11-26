// Package audit provides the first durable, fixture-only audit workflow.
// It does not yet run Recon/Hunt/Validate or enable paid model requests.
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/state"
)

const FixtureSchema = "tekmerion-fixture-audit-1"

type Manifest struct {
	Schema           string              `json:"schema_version"`
	Mode             string              `json:"mode"`
	ContractDir      string              `json:"contract_directory"`
	PinSHA           string              `json:"pin_sha256"`
	ContractRevision string              `json:"contract_revision"`
	Budget           *state.BudgetConfig `json:"budget,omitempty"`
}

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contract(dir string) ([]byte, error) {
	pinPath := filepath.Join(dir, "..", "PIN.json")
	pin, err := ariadne.LoadPin(pinPath)
	if err != nil {
		return nil, err
	}
	if err := pin.Verify(dir); err != nil {
		return nil, err
	}
	return os.ReadFile(pinPath)
}

// StartFixture saves a pinned input and a complete deterministic task queue.
func StartFixture(ctx context.Context, dir, contractDir string) error {
	return StartFixtureBudget(ctx, dir, contractDir, nil)
}

// StartFixtureBudget records a budget for local status/report testing. Fixture
// tasks remain local, consume no LLM budget and never call a provider.
func StartFixtureBudget(ctx context.Context, dir, contractDir string, budget *state.BudgetConfig) error {
	if budget != nil {
		if err := budget.Validate(); err != nil {
			return err
		}
	}

	absolute, err := filepath.Abs(contractDir)
	if err != nil {
		return err
	}
	pinRaw, err := contract(absolute)
	if err != nil {
		return err
	}
	f, err := ariadne.NewFixture(absolute, ariadne.Recorder{})
	if err != nil {
		return err
	}
	s, err := state.Create(ctx, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	m := Manifest{Schema: FixtureSchema, Mode: "fixture", ContractDir: absolute, PinSHA: hash(pinRaw), ContractRevision: ariadne.ContractRevision, Budget: budget}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	a, err := s.Put(ctx, raw, "application/json")
	if err != nil {
		return err
	}
	inputs := []state.TaskInput{}
	for _, path := range f.Requests() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		head, err := ariadne.ParseRequest(raw)
		if err != nil {
			return err
		}
		artifact, err := s.Put(ctx, raw, "application/json")
		if err != nil {
			return err
		}
		inputs = append(inputs, state.TaskInput{ID: head.RequestID, Stage: head.Operation, InputSHA: artifact.SHA})
	}
	if budget != nil {
		if _, err := s.StartBudget(ctx, a.SHA, inputs, *budget); err != nil {
			return err
		}
	} else if _, err := s.Start(ctx, a.SHA, inputs); err != nil {
		return err
	}
	return nil
}

type Evidence struct {
	Schema          string `json:"schema_version"`
	Provenance      string `json:"provenance"`
	Outcome         string `json:"outcome"`
	ValidationScope string `json:"validation_scope,omitempty"`
	Exit            int    `json:"exit"`
	RequestSHA      string `json:"request_sha256"`
	ResponseSHA     string `json:"response_sha256,omitempty"`
	StderrSHA       string `json:"stderr_sha256,omitempty"`
	Diagnostic      string `json:"diagnostic,omitempty"`
}

// ResumeFixture runs only unfinished tasks. A live lease is respected; its
// owner must finish or the recorded lease must expire before reassignment.
func ResumeFixture(ctx context.Context, dir string) error {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	raw, err := s.Get(ctx, snapshot.Run.ManifestSHA)
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Schema != FixtureSchema || m.Mode != "fixture" || m.ContractRevision != ariadne.ContractRevision {
		return fmt.Errorf("unsupported audit manifest; only %s fixture work is enabled", FixtureSchema)
	}
	if snapshot.Run.Status == "failed" {
		return fmt.Errorf("fixture run failed; inspect status or report for saved diagnostics")
	}
	if snapshot.Run.Status != "running" {
		return nil
	}
	pinRaw, err := contract(m.ContractDir)
	if err != nil {
		return err
	}
	if hash(pinRaw) != m.PinSHA {
		return fmt.Errorf("contract pin changed since run creation")
	}
	f, err := ariadne.NewFixture(m.ContractDir, ariadne.Recorder{})
	if err != nil {
		return err
	}
	worker := "fixture-" + rand.Text()
	for _, task := range snapshot.Tasks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if task.Status == "completed" || task.Status == "failed" {
			continue
		}
		claim, err := s.Claim(ctx, snapshot.Run.ID, task.ID, worker, time.Minute)
		if err != nil {
			return err
		}
		if err := runFixtureTask(ctx, s, f, *claim, task); err != nil {
			return err
		}
	}
	final, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	if final.Run.Status == "failed" {
		return fmt.Errorf("fixture run failed; inspect status or report for saved diagnostics")
	}
	return nil
}
func runFixtureTask(ctx context.Context, s *state.Store, f *ariadne.Fixture, claim state.Claim, task state.Task) error {
	// Cancellation still receives a bounded local commit window, so a graceful
	// stop need not wait for lease expiry. A hard kill is recovered by the lease.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	raw, err := s.Get(saveCtx, task.InputSHA)
	if err != nil {
		return finishError(saveCtx, s, claim, err)
	}
	head, err := ariadne.ParseRequest(raw)
	if err != nil {
		return finishError(saveCtx, s, claim, err)
	}
	if head.RequestID != task.ID || head.Operation != task.Stage {
		return finishError(saveCtx, s, claim, fmt.Errorf("task input identity differs from saved queue"))
	}
	if err := ctx.Err(); err != nil {
		if finishErr := s.Finish(saveCtx, claim, "interrupted", "", err.Error()); finishErr != nil {
			return finishErr
		}
		return err
	}
	res, queryErr := f.Query(ctx, raw)
	evidence := Evidence{Schema: "tekmerion-static-attempt-1", Provenance: "fixture", Outcome: "failure", RequestSHA: task.InputSHA}
	if res != nil {
		evidence.Outcome, evidence.ValidationScope, evidence.Exit = res.Outcome, res.ValidationScope, res.Exit
		if res.RawResponse != nil {
			a, err := s.Put(saveCtx, res.RawResponse, "application/json")
			if err != nil {
				return err
			}
			evidence.ResponseSHA = a.SHA
		}
		if len(res.Stderr) > 0 {
			a, err := s.Put(saveCtx, res.Stderr, "text/plain")
			if err != nil {
				return err
			}
			evidence.StderrSHA = a.SHA
		}
	}
	outcome := "completed"
	if queryErr != nil {
		outcome = "failed"
		evidence.Diagnostic = queryErr.Error()
	}
	if ctx.Err() != nil {
		outcome = "interrupted"
		evidence.Diagnostic = ctx.Err().Error()
	}
	payload, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	a, err := s.Put(saveCtx, payload, "application/json")
	if err != nil {
		return err
	}
	if err := s.Finish(saveCtx, claim, outcome, a.SHA, evidence.Diagnostic); err != nil {
		return err
	}
	return ctx.Err()
}
func finishError(ctx context.Context, s *state.Store, claim state.Claim, cause error) error {
	if err := s.Finish(ctx, claim, "failed", "", cause.Error()); err != nil {
		return err
	}
	return cause
}
