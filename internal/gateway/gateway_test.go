package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/openrouter"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/state"
)

func setup(t *testing.T, attempts int) (*state.Store, string) {
	t.Helper()
	s, err := state.Create(context.Background(), filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now()
	prices := pricing.Snapshot{Schema: pricing.SnapshotSchema, Source: "synthetic:local-test", Currency: "USD", RetrievedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), Routes: []pricing.Route{{Model: "test/model", Provider: "provider", Input: "0.000001", Output: "0.000001", Request: "0", Complete: true, ReasoningIncluded: true}}}
	raw, _ := json.Marshal(prices)
	a, err := s.Put(context.Background(), raw, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	task := Task{Schema: TaskSchema, PricingSHA: a.SHA, MaxAttempts: attempts, TimeoutSeconds: 1, Request: llm.Request{Role: "recon", Model: "test/model", Provider: "provider", PromptRevision: "recon-test-1", InputTokenBound: 100, MaxOutputTokens: 20, JSONOutput: true, Messages: []llm.Message{{Role: "user", Content: "Return architecture JSON"}}}}
	raw, _ = json.Marshal(task)
	input, err := s.Put(context.Background(), raw, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	budget := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: state.Dollar, MaxRequests: 10, MaxTokens: 2000, WallTimeSeconds: 60}
	run, err := s.StartBudget(context.Background(), input.SHA, []state.TaskInput{{ID: "recon", Stage: "recon", InputSHA: input.SHA, Paid: true}}, budget)
	if err != nil {
		t.Fatal(err)
	}
	return s, run.ID
}
func response(id string, cost string, content string) string {
	usage := map[string]any{"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}
	if cost != "" {
		usage["cost"] = json.Number(cost)
	}
	raw, _ := json.Marshal(map[string]any{"id": id, "model": "test/model", "provider": "provider", "choices": []any{map[string]any{"message": map[string]string{"content": content}, "finish_reason": "stop"}}, "usage": usage})
	return string(raw)
}
func client(t *testing.T, handler http.HandlerFunc) *openrouter.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := openrouter.New(openrouter.Config{Endpoint: server.URL, APIKey: "gateway-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestHTTPTaskReservationSettlementAndReplay(t *testing.T) {
	s, _ := setup(t, 1)
	var calls atomic.Int32
	provider := client(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(response("one", "0", `{"architecture":"grounded"}`)))
	})
	validate := func(content string) error {
		var result map[string]string
		if err := json.Unmarshal([]byte(content), &result); err != nil {
			return err
		}
		if result["architecture"] == "" {
			return errors.New("missing architecture")
		}
		return nil
	}
	result, err := Execute(context.Background(), s, "recon", provider, validate)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cost == nil || *result.Cost != 0 {
		t.Fatal("known zero cost lost")
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Run.Status != "completed" || len(snap.Attempts) != 1 || snap.Budget.Requests != 1 || snap.Budget.UnsettledRequests != 0 || snap.Budget.Reservations[0].DispatchedAt == nil {
		t.Fatalf("untracked network request: %+v", snap)
	}
	if _, err := Execute(context.Background(), s, "recon", provider, validate); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("completed task dispatched twice")
	}
	if err := s.Verify(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	for _, a := range snap.Artifacts {
		raw, err := s.Get(context.Background(), a.SHA)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "gateway-secret") {
			t.Fatal("API credential saved as evidence")
		}
	}
}
func TestUncertainHTTPRetryKeepsOldReservation(t *testing.T) {
	s, _ := setup(t, 2)
	var calls atomic.Int32
	provider := client(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			w.Write([]byte(`{"error":{"code":503}}`))
			return
		}
		w.Write([]byte(response("retry", "0", `{"ok":true}`)))
	})
	if _, err := Execute(context.Background(), s, "recon", provider, nil); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(snap.Attempts) != 2 || snap.Attempts[0].Outcome != "interrupted" || snap.Budget.Requests != 2 || snap.Budget.UnsettledRequests != 1 || snap.Budget.Outstanding != 120000 || len(snap.Budget.Uncertain) != 1 {
		t.Fatalf("uncertain request released or retry unreserved: %+v", snap)
	}
}
func TestMissingCostAndHTTP200ErrorCannotBecomeKnownFreeSuccess(t *testing.T) {
	for _, kind := range []string{"missing-cost", "error-200", "bad-content", "route-change"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := setup(t, 1)
			provider := client(t, func(w http.ResponseWriter, r *http.Request) {
				body := response("one", "0", `{"ok":true}`)
				switch kind {
				case "missing-cost":
					body = response("one", "", `{"ok":true}`)
				case "error-200":
					body = `{"id":"one","error":{"code":503},"usage":{"cost":0}}`
				case "bad-content":
					body = response("one", "0", `{}`)
				case "route-change":
					body = strings.Replace(body, `"provider":"provider"`, `"provider":"other"`, 1)
				}
				w.Write([]byte(body))
			})
			validator := func(content string) error {
				if kind == "bad-content" {
					return errors.New("missing required field")
				}
				return nil
			}
			_, err := Execute(context.Background(), s, "recon", provider, validator)
			if (err != nil) != (kind != "missing-cost") {
				t.Fatalf("unexpected decision: %v", err)
			}
			snap, err := s.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if kind == "missing-cost" {
				if snap.Budget.UnsettledRequests != 1 || snap.Budget.Outstanding == 0 {
					t.Fatal("missing cost released")
				}
			} else if snap.Run.Status != "failed" {
				t.Fatal("provider or validation error became success")
			}
			if kind == "route-change" && len(snap.Budget.Halts) != 1 {
				t.Fatal("unknown returned route did not stop admission")
			}
		})
	}
}
func TestRoleValidationRetriesAreBoundedAndAccounted(t *testing.T) {
	s, _ := setup(t, 2)
	var calls atomic.Int32
	provider := client(t, func(w http.ResponseWriter, r *http.Request) {
		id := calls.Add(1)
		w.Write([]byte(response(fmt.Sprintf("gen-%d", id), "0", `{}`)))
	})
	if _, err := Execute(context.Background(), s, "recon", provider, func(string) error { return errors.New("invalid citation") }); err == nil {
		t.Fatal("invalid structured output accepted")
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(snap.Attempts) != 2 || snap.Run.Status != "failed" || snap.Budget.Requests != 2 || snap.Budget.Settled != 0 {
		t.Fatal("unbounded or unaccounted corrective retries")
	}
	if _, err := Execute(context.Background(), s, "recon", provider, nil); err == nil || calls.Load() != 2 {
		t.Fatal("failed terminal task restarted")
	}
}
func TestNoHTTPOnPreflightOrBudgetFailure(t *testing.T) {
	s, _ := setup(t, 2)
	var calls atomic.Int32
	provider := client(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Execute(cancelled, s, "recon", provider, nil); err == nil {
		t.Fatal("cancelled work admitted")
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP before admission")
	}
	raw, _ := json.Marshal(state.PriceBound{Schema: state.PriceBoundSchema, Currency: "USD", Source: "configured_conservative", Model: "test/model", Provider: "provider", MaxCost: state.Dollar, MaxTokens: 120, ValidUntil: time.Now().Add(time.Hour).UnixNano()})
	price, err := s.Put(context.Background(), raw, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := s.Put(context.Background(), []byte(`{"prompt":"previous uncertain request"}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimRequest(context.Background(), snap.Run.ID, "recon", "old-worker", time.Minute, state.RequestBound{ID: "uncertain", Model: "test/model", Provider: "provider", PricingSHA: price.SHA, RequestSHA: prompt.SHA, MaxCost: state.Dollar, MaxTokens: 120})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(context.Background(), *claim, "interrupted", "", "delivery uncertain"); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), s, "recon", provider, nil); !errors.Is(err, state.ErrBudget) {
		t.Fatalf("budget failure bypassed: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP called despite exhausted reservation budget")
	}
}
func TestTaskTimeoutBound(t *testing.T) {
	task := Task{Schema: TaskSchema, PricingSHA: "sha256:p", MaxAttempts: 1, Request: llm.Request{Role: "hunt", Model: "test/model", Provider: "provider", PromptRevision: "hunt-test-1", InputTokenBound: 100, MaxOutputTokens: 20, JSONOutput: true, Messages: []llm.Message{{Role: "user", Content: "Return JSON"}}}}
	for _, tc := range []struct {
		seconds int
		ok      bool
	}{{0, false}, {1, true}, {llm.MaxTimeoutSeconds, true}, {llm.MaxTimeoutSeconds + 1, false}} {
		task.TimeoutSeconds = tc.seconds
		raw, _ := json.Marshal(task)
		if _, err := Parse(raw); (err == nil) != tc.ok {
			t.Errorf("timeout %d s: accepted=%v, want %v (%v)", tc.seconds, err == nil, tc.ok, err)
		}
	}
	if llm.MaxTimeoutSeconds < 300 {
		t.Fatalf("request timeout cap %d s is below what slow reasoning models need", llm.MaxTimeoutSeconds)
	}
}
