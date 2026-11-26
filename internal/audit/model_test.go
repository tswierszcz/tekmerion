package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type localProvider struct{}

func (localProvider) Complete(context.Context, llm.Request) (*llm.Result, error) {
	cost := state.Money(1000)
	tokens := int64(12)
	return &llm.Result{HTTPStatus: 200, ID: "local-gen", Model: "test/model", Provider: "provider", Cost: &cost, Tokens: &tokens, Content: `{"ok":true}`, FinishReason: "stop", RawResponse: []byte(`{"fixture":"local-provider"}`)}, nil
}
func TestModelLedgerForecastAndActualCosts(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Create(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	put := func(raw []byte) string {
		t.Helper()
		a, err := s.Put(ctx, raw, "application/json")
		if err != nil {
			t.Fatal(err)
		}
		return a.SHA
	}
	now := time.Now()
	prices := pricing.Snapshot{Schema: pricing.SnapshotSchema, Source: "synthetic:local", Currency: "USD", RetrievedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), Routes: []pricing.Route{{Model: "test/model", Provider: "provider", Input: "0.000001", Output: "0.000002", Request: "0", Complete: true, ReasoningIncluded: true}}}
	priceRaw, _ := json.Marshal(prices)
	priceSHA := put(priceRaw)
	request := llm.Request{Role: "recon", Model: "test/model", Provider: "provider", PromptRevision: "test-1", Messages: []llm.Message{{Role: "user", Content: "Return JSON"}}, InputTokenBound: 100, MaxOutputTokens: 20, JSONOutput: true}
	requestRaw, _ := json.Marshal(request)
	requestSHA := put(requestRaw)
	task := gateway.Task{Schema: gateway.TaskSchema, Request: request, PricingSHA: priceSHA, MaxAttempts: 1, TimeoutSeconds: 1}
	taskRaw, _ := json.Marshal(task)
	taskSHA := put(taskRaw)
	budget := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: state.Dollar, MaxRequests: 10, MaxTokens: 1000, WallTimeSeconds: 3600}
	manifest := gateway.Manifest{Schema: gateway.RunSchema, Mode: "model", TaskID: "recon", RequestSHA: requestSHA, PricingSHA: priceSHA, Budget: budget}
	manifestRaw, _ := json.Marshal(manifest)
	manifestSHA := put(manifestRaw)
	run, err := s.StartBudget(ctx, manifestSHA, []state.TaskInput{{ID: "recon", Stage: "recon", InputSHA: taskSHA, Paid: true}}, budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Execute(ctx, s, "recon", localProvider{}, nil); err != nil {
		t.Fatal(err)
	}
	scenario := pricing.Scenario{Requests: 1, Input: 100, Output: 20}
	plan := pricing.Plan{Schema: pricing.PlanSchema, TargetIdentity: manifestSHA, Scope: "local provider fixture", Assumptions: []string{"one synthetic request"}, Roles: []pricing.Role{{Stage: "recon", Model: "test/model", Provider: "provider", Low: scenario, Base: scenario, High: scenario, MaxRequests: 1, InputLimit: 100, OutputLimit: 20}}}
	planRaw, _ := json.Marshal(plan)
	estimate, err := pricing.Build(planRaw, priceRaw, now, &budget)
	if err != nil {
		t.Fatal(err)
	}
	estimateRaw, _ := json.Marshal(estimate)
	if err := s.AddForecast(ctx, run.ID, put(estimateRaw), put(planRaw), priceSHA); err != nil {
		t.Fatal(err)
	}
	md, err := Report(ctx, dir, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(md, []byte("Provenance: **model request**")) || bytes.Contains(md, []byte("Paid model requests: **0**")) || !bytes.Contains(md, []byte("| recon | test/model / provider | 0.000140000 | 0.000140000 | 0.000001000 | 0.000000000 |")) {
		t.Fatalf("incorrect forecast/observed report: %s", md)
	}
	before, err := Report(ctx, dir, "json")
	if err != nil {
		t.Fatal(err)
	}
	after, err := Report(ctx, dir, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("model report not deterministic")
	}
}
