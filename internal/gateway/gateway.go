// Package gateway connects one immutable bounded model task to durable state.
// Retries are explicit new reservations; the HTTP provider never retries itself.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/state"
)

const TaskSchema = "tekmerion-model-task-1"
const RunSchema = "tekmerion-model-run-1"

type Manifest struct {
	Schema     string             `json:"schema_version"`
	Mode       string             `json:"mode"`
	TaskID     string             `json:"task_id"`
	RequestSHA string             `json:"request_sha256"`
	PricingSHA string             `json:"pricing_sha256"`
	Budget     state.BudgetConfig `json:"budget"`
}

type Task struct {
	Schema         string      `json:"schema_version"`
	Request        llm.Request `json:"request"`
	PricingSHA     string      `json:"pricing_sha256"`
	MaxAttempts    int         `json:"max_attempts"`
	TimeoutSeconds int         `json:"timeout_seconds"`
}
type Execution struct {
	Schema      string      `json:"schema_version"`
	RequestID   string      `json:"request_id"`
	RequestSHA  string      `json:"request_sha256"`
	ResponseSHA string      `json:"response_sha256,omitempty"`
	Result      *llm.Result `json:"result"`
	Diagnostic  string      `json:"diagnostic,omitempty"`
}

func Parse(raw []byte) (Task, error) {
	var t Task
	if err := jsonx.Decode(raw, &t, false); err != nil {
		return t, err
	}
	if t.Schema != TaskSchema || t.MaxAttempts < 1 || t.MaxAttempts > 5 || t.TimeoutSeconds < 1 || t.TimeoutSeconds > llm.MaxTimeoutSeconds || t.PricingSHA == "" {
		return t, fmt.Errorf("model task requires schema, saved pricing and bounded attempts/deadline")
	}
	return t, t.Request.Validate()
}

// Execute runs only the requested task from the saved queue. No source is
// selected implicitly. validate checks the role-specific structured output;
// provider-level JSON validation remains in the HTTP adapter as a first layer.
func Execute(ctx context.Context, s *state.Store, taskID string, provider llm.Provider, validate func(string) error) (*llm.Result, error) {
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	var queued *state.Task
	for i := range snapshot.Tasks {
		if snapshot.Tasks[i].ID == taskID {
			queued = &snapshot.Tasks[i]
			break
		}
	}
	if queued == nil {
		return nil, fmt.Errorf("unknown model task")
	}
	raw, err := s.Get(ctx, queued.InputSHA)
	if err != nil {
		return nil, err
	}
	task, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if !queued.Paid || queued.Stage != task.Request.Role {
		return nil, fmt.Errorf("saved task role differs from paid queue")
	}
	if checker, ok := provider.(interface{ Check(llm.Request) error }); ok {
		if err := checker.Check(task.Request); err != nil {
			return nil, err
		}
	}
	// A completed task is replayed from its original evidence, not dispatched.
	for i := len(snapshot.Attempts) - 1; i >= 0; i-- {
		a := snapshot.Attempts[i]
		if a.TaskID == taskID && a.Outcome == "completed" {
			raw, err := s.Get(ctx, a.ResultSHA)
			if err != nil {
				return nil, err
			}
			var execution Execution
			if err := jsonx.Decode(raw, &execution, false); err != nil {
				return nil, err
			}
			return execution.Result, nil
		}
	}
	if queued.Status == "failed" {
		return nil, fmt.Errorf("model task previously failed; inspect saved evidence")
	}
	priceRaw, err := s.Get(ctx, task.PricingSHA)
	if err != nil {
		return nil, err
	}
	prices, err := pricing.ParseSnapshot(priceRaw)
	if err != nil {
		return nil, err
	}
	attemptCount := 0
	for _, a := range snapshot.Attempts {
		if a.TaskID == taskID {
			attemptCount++
		}
	}
	worker := "gateway-" + rand.Text()
	for attemptCount < task.MaxAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cost, validUntil, source, err := pricing.Bound(prices, task.Request.Model, task.Request.Provider, task.Request.InputTokenBound, task.Request.MaxOutputTokens, time.Now())
		if err != nil {
			return nil, err
		}
		// The original normalized snapshot is linked even for an explicit manual
		// ceiling; the state gate independently rechecks the derived bound's TTL.
		boundSource := "configured_conservative"
		if source == "snapshot_cache_miss" {
			boundSource = source
		}
		price := state.PriceBound{Schema: state.PriceBoundSchema, Currency: "USD", Source: boundSource, Model: task.Request.Model, Provider: task.Request.Provider, MaxCost: cost, MaxTokens: task.Request.InputTokenBound + task.Request.MaxOutputTokens, ValidUntil: validUntil.UnixNano(), SnapshotSHA: task.PricingSHA}
		priceBytes, err := json.Marshal(price)
		if err != nil {
			return nil, err
		}
		priceArtifact, err := s.Put(ctx, priceBytes, "application/json")
		if err != nil {
			return nil, err
		}
		requestBytes, err := json.Marshal(task.Request)
		if err != nil {
			return nil, err
		}
		requestArtifact, err := s.Put(ctx, requestBytes, "application/json")
		if err != nil {
			return nil, err
		}
		requestID := "model-" + rand.Text()
		bound := state.RequestBound{ID: requestID, Model: task.Request.Model, Provider: task.Request.Provider, PricingSHA: priceArtifact.SHA, RequestSHA: requestArtifact.SHA, MaxCost: cost, MaxTokens: price.MaxTokens}
		ttl := time.Duration(task.TimeoutSeconds+15) * time.Second
		claim, err := s.ClaimRequest(ctx, snapshot.Run.ID, taskID, worker, ttl, bound)
		if err != nil {
			return nil, err
		}
		attemptCount++
		if err := s.Dispatch(ctx, *claim, requestID); err != nil {
			local, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			finishErr := s.Finish(local, *claim, "interrupted", "", err.Error())
			cancel()
			if finishErr != nil {
				return nil, finishErr
			}
			return nil, err
		}
		deadline := time.Now().Add(time.Duration(task.TimeoutSeconds) * time.Second)
		if snapshot.Budget != nil {
			budgetDeadline := time.Unix(0, snapshot.Budget.Deadline)
			if budgetDeadline.Before(deadline) {
				deadline = budgetDeadline
			}
		}
		callCtx, cancel := context.WithDeadline(ctx, deadline)
		result, callErr := provider.Complete(callCtx, task.Request)
		cancel()
		if result == nil {
			result = &llm.Result{Diagnostic: "provider returned no result; charge uncertain"}
			if callErr == nil {
				callErr = fmt.Errorf("provider returned no result")
			}
		}
		if callErr == nil && validate != nil {
			if err := validate(result.Content); err != nil {
				callErr = fmt.Errorf("role-specific structured output validation failed")
				result.Retryable = true
			}
		}
		local, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if result.RouteMismatch || result.PromptTokens != nil && *result.PromptTokens > task.Request.InputTokenBound || result.CompletionTokens != nil && *result.CompletionTokens > task.Request.MaxOutputTokens {
			if err := s.HaltAdmission(local, snapshot.Run.ID, requestID, "returned route or per-dimension token usage exceeds configured bounds"); err != nil {
				saveCancel()
				return result, err
			}
			if callErr == nil {
				callErr = fmt.Errorf("reported token dimension exceeds its bound")
			}
			result.Retryable = false
		}
		execution := Execution{Schema: "tekmerion-model-execution-1", RequestID: requestID, RequestSHA: requestArtifact.SHA, Result: result}
		if callErr != nil {
			execution.Diagnostic = callErr.Error()
		}
		if result.RawResponse != nil {
			a, err := s.Put(local, result.RawResponse, "application/json")
			if err != nil {
				saveCancel()
				return result, err
			}
			execution.ResponseSHA = a.SHA
		}
		executionRaw, err := json.Marshal(execution)
		if err != nil {
			saveCancel()
			return result, err
		}
		evidence, err := s.Put(local, executionRaw, "application/json")
		if err != nil {
			saveCancel()
			return result, err
		}

		if result.Cost != nil && result.ID != "" {
			if err := s.Settle(local, snapshot.Run.ID, requestID, "openrouter:"+result.ID, *result.Cost, result.Tokens, evidence.SHA); err != nil {
				saveCancel()
				return result, err
			}
		} else {
			if err := s.ObserveUncertain(local, snapshot.Run.ID, requestID, requestID+":charge", "cost or generation identity unavailable; reservation retained", evidence.SHA); err != nil {
				saveCancel()
				return result, err
			}
		}
		retry := callErr != nil && result.Retryable && attemptCount < task.MaxAttempts && ctx.Err() == nil
		outcome := "completed"
		if callErr != nil {
			outcome = "failed"
		}
		if retry || ctx.Err() != nil {
			outcome = "interrupted"
		}
		diagnostic := ""
		if callErr != nil {
			diagnostic = callErr.Error()
		}
		err = s.Finish(local, *claim, outcome, evidence.SHA, diagnostic)
		saveCancel()
		if err != nil {
			return result, err
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if !retry {
			return result, callErr
		}
		delay := time.Duration(max(int64(100), min(result.RetryAfterMS, int64(30000)))) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, ctx.Err()
		case <-timer.C:
		}

	}
	return nil, fmt.Errorf("model task attempt cap reached")
}
