package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func budgetRun(t *testing.T, s *Store, limit, validation, report Money, stages ...string) *Run {
	t.Helper()
	sha := put(t, s, `{"context":"pinned"}`)
	inputs := []TaskInput{}
	for _, stage := range stages {
		inputs = append(inputs, TaskInput{ID: stage, Stage: stageName(stage), InputSHA: sha, Paid: true})
	}
	config := BudgetConfig{Schema: BudgetSchema, Currency: "USD", Limit: limit, ValidationReserve: validation, ReportingReserve: report, MaxRequests: 20, MaxTokens: 1000, WallTimeSeconds: 3600}
	r, err := s.StartBudget(context.Background(), sha, inputs, config)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func stageName(id string) string {
	if id == "validate" || id == "report" || id == "recon" {
		return id
	}
	return "hunt"
}
func request(t *testing.T, s *Store, id string, cost Money) RequestBound {
	t.Helper()
	price := PriceBound{Schema: PriceBoundSchema, Currency: "USD", Source: "configured_conservative", Model: "fixture-model", Provider: "fixture-provider", MaxCost: cost, MaxTokens: 10, ValidUntil: s.now().Add(time.Hour).UnixNano()}
	raw, err := json.Marshal(price)
	if err != nil {
		t.Fatal(err)
	}
	return RequestBound{ID: id, Model: price.Model, Provider: price.Provider, PricingSHA: put(t, s, string(raw)), RequestSHA: put(t, s, `{"prompt":"bounded"}`), MaxCost: cost, MaxTokens: 10}
}
func accounting(t *testing.T, s *Store) *BudgetSnapshot {
	t.Helper()
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Budget == nil {
		t.Fatal("missing budget")
	}
	return snap.Budget
}

func TestMoneyExactDecimal(t *testing.T) {
	for input, want := range map[string]Money{"0": 0, "0.000000001": 1, "12.123456789": 12123456789, "9223372036.854775807": Money(math.MaxInt64)} {
		got, err := ParseMoney(input)
		if err != nil || got != want {
			t.Fatalf("%s: %v %v", input, got, err)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var back Money
		if err := json.Unmarshal(raw, &back); err != nil || back != got {
			t.Fatalf("roundtrip: %s %v", raw, err)
		}
	}
	for _, input := range []string{"", "-1", "1e3", "NaN", "1.", ".1", "0.0000000001", "9223372036.854775808"} {
		if _, err := ParseMoney(input); err == nil {
			t.Fatalf("bad money accepted: %s", input)
		}
	}
	if Money(math.MinInt64).String() != "-9223372036.854775808" {
		t.Fatal("signed availability overflow")
	}
	if _, err := add64(math.MaxInt64, 1); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestPaidClaimAndLastAffordableRequestAreAtomic(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 100, 20, 10, "hunt-a", "hunt-b")
	a, b := request(t, s, "request-a", 70), request(t, s, "request-b", 70)
	if _, err := s.Claim(ctx, run.ID, "hunt-a", "local-bypass", time.Minute); err == nil {
		t.Fatal("paid task acquired without reservation")
	}
	other, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	gate := make(chan struct{})
	outcomes := make(chan error, 2)
	var workers sync.WaitGroup
	for i, db := range []*Store{s, other} {
		workers.Add(1)
		go func(i int, db *Store) {
			defer workers.Done()
			<-gate
			task, bound := "hunt-a", a
			if i == 1 {
				task, bound = "hunt-b", b
			}
			_, err := db.ClaimRequest(ctx, run.ID, task, "worker", time.Minute, bound)
			outcomes <- err
		}(i, db)
	}
	close(gate)
	workers.Wait()
	close(outcomes)
	admitted, exhausted := 0, 0
	for err := range outcomes {
		if err == nil {
			admitted++
		} else if errors.Is(err, ErrBudget) {
			exhausted++
		} else {
			t.Fatal(err)
		}
	}
	if admitted != 1 || exhausted != 1 {
		t.Fatalf("admitted=%d exhausted=%d", admitted, exhausted)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Attempts) != 1 || snap.Budget.Outstanding != 70 || snap.Budget.Available != 0 || snap.Budget.ValidationProtected != 20 || snap.Budget.ReportingProtected != 10 {
		t.Fatalf("partial claim or protected funds spent: %+v", snap)
	}
	pending := 0
	for _, task := range snap.Tasks {
		if task.Status == "pending" {
			pending++
		}
	}
	if pending != 1 {
		t.Fatal("unaffordable task was claimed")
	}
}

func TestUncertainChargeSurvivesLeaseExpiryRestartAndRetry(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	clock := time.Now()
	s.now = func() time.Time { return clock }
	run := budgetRun(t, s, 100, 20, 10, "hunt")
	bound := request(t, s, "original", 30)
	first, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker-a", time.Minute, bound)
	if err != nil {
		t.Fatal(err)
	}
	evidence := put(t, s, `{"error":"timeout; upstream delivery unknown"}`)
	if err := s.ObserveUncertain(ctx, run.ID, bound.ID, "timeout-1", "delivery and charge unknown", evidence); err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveUncertain(ctx, run.ID, bound.ID, "timeout-1", "delivery and charge unknown", evidence); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	clock = clock.Add(2 * time.Minute)
	recovered.now = func() time.Time { return clock }
	retry := request(t, recovered, "retry", 30)
	second, err := recovered.ClaimRequest(ctx, run.ID, "hunt", "worker-b", time.Minute, retry)
	if err != nil {
		t.Fatal(err)
	}
	before := accounting(t, recovered)
	if before.Outstanding != 60 || before.Available != 10 || len(before.Uncertain) != 1 || before.Requests != 2 {
		t.Fatalf("lost conservative charge: %+v", before)
	}
	if err := recovered.Finish(ctx, *first, "completed", "", ""); err == nil {
		t.Fatal("expired worker delivered a result")
	}
	receipt := put(t, recovered, `{"cost":0}`)
	if err := recovered.Settle(ctx, run.ID, bound.ID, "gateway:original", 0, nil, receipt); err != nil {
		t.Fatal(err)
	}
	original := accounting(t, recovered)
	if original.Reservations[0].Charge == nil || *original.Reservations[0].Charge != 0 || original.Outstanding != 30 || original.Available != 40 {
		t.Fatalf("zero treated as missing: %+v", original)
	}
	if err := recovered.Settle(ctx, run.ID, bound.ID, "gateway:original", 0, nil, receipt); err != nil {
		t.Fatal(err)
	}
	after := accounting(t, recovered)
	oldJSON, _ := json.Marshal(original)
	newJSON, _ := json.Marshal(after)
	if string(oldJSON) != string(newJSON) {
		t.Fatal("duplicate receipt changed accounting")
	}
	if err := recovered.Settle(ctx, run.ID, bound.ID, "gateway:original", 1, nil, receipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed receipt accepted: %v", err)
	}
	if err := recovered.Finish(ctx, *second, "completed", receipt, ""); err != nil {
		t.Fatal(err)
	}
	// Even a terminal run must accept late reconciliation of an old request.
	tokens := int64(3)
	if err := recovered.Settle(ctx, run.ID, retry.ID, "gateway:retry", 20, &tokens, receipt); err != nil {
		t.Fatal(err)
	}
	final := accounting(t, recovered)
	if final.Outstanding != 0 || final.Settled != 20 || final.Available != 50 || final.Tokens != 13 {
		t.Fatalf("wrong final accounting: %+v", final)
	}
}

func TestProtectedReservesTransferAndRefundWithoutDoubleCounting(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 100, 20, 10, "hunt", "validate", "report")
	hunt, err := s.ClaimRequest(ctx, run.ID, "hunt", "hunter", time.Minute, request(t, s, "hunt-1", 70))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := s.ClaimRequest(ctx, run.ID, "validate", "validator", time.Minute, request(t, s, "validate-1", 20))
	if err != nil {
		t.Fatal(err)
	}
	snap := accounting(t, s)
	if snap.Available != 0 || snap.ValidationProtected != 0 || snap.ReportingProtected != 10 || snap.Outstanding != 90 {
		t.Fatalf("double-counted stage transfer: %+v", snap)
	}
	receipt := put(t, s, `{"cost":0.000000005}`)
	used := int64(1)
	if err := s.Settle(ctx, run.ID, "validate-1", "provider:validation", 5, &used, receipt); err != nil {
		t.Fatal(err)
	}
	snap = accounting(t, s)
	if snap.ValidationProtected != 15 || snap.Settled != 5 || snap.Available != 0 {
		t.Fatalf("unused validation funds leaked to Hunt: %+v", snap)
	}
	if err := s.ReserveRequest(ctx, *hunt, request(t, s, "hunt-2", 1)); !errors.Is(err, ErrBudget) {
		t.Fatalf("Hunt consumed restored protection: %v", err)
	}
	if err := s.ReserveRequest(ctx, *validator, request(t, s, "validate-2", 15)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimRequest(ctx, run.ID, "report", "reporter", time.Minute, request(t, s, "report-1", 10)); err != nil {
		t.Fatal(err)
	}
	snap = accounting(t, s)
	if snap.Available != 0 || snap.ValidationProtected != 0 || snap.ReportingProtected != 0 || snap.Outstanding != 95 || snap.Settled != 5 {
		t.Fatalf("invalid protected allocation: %+v", snap)
	}
}

func TestBoundDiscrepancyHaltsNewPaidWork(t *testing.T) {
	for _, byTokens := range []bool{false, true} {
		t.Run(map[bool]string{false: "money", true: "tokens"}[byTokens], func(t *testing.T) {
			s, _ := newStore(t)
			ctx := context.Background()
			run := budgetRun(t, s, 100, 0, 0, "hunt-a", "hunt-b")
			first, err := s.ClaimRequest(ctx, run.ID, "hunt-a", "a", time.Minute, request(t, s, "one", 10))
			if err != nil {
				t.Fatal(err)
			}
			cost := Money(11)
			tokens := int64(1)
			if byTokens {
				cost = 5
				tokens = 11
			}
			receipt := put(t, s, `{"observed":"above-bound"}`)
			if err := s.Settle(ctx, run.ID, "one", "provider:one", cost, &tokens, receipt); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimRequest(ctx, run.ID, "hunt-b", "b", time.Minute, request(t, s, "two", 1)); !errors.Is(err, ErrHalted) {
				t.Fatalf("new paid work admitted: %v", err)
			}
			if err := s.ReserveRequest(ctx, *first, request(t, s, "three", 1)); !errors.Is(err, ErrHalted) {
				t.Fatalf("tool loop continued after discrepancy: %v", err)
			}
			snap := accounting(t, s)
			if len(snap.Halts) != 1 || snap.Settled != cost || snap.Requests != 1 {
				t.Fatalf("lost discrepancy: %+v", snap)
			}
		})
	}
}

func TestRequestTokenTimeAndPricingLimits(t *testing.T) {
	for _, kind := range []string{"request-cap", "token-cap", "deadline", "unknown-price", "expired-price", "changed-route", "underpriced", "reserves-only"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			ctx := context.Background()
			sha := put(t, s, `{}`)
			config := BudgetConfig{Schema: BudgetSchema, Currency: "USD", Limit: 100, MaxRequests: 2, MaxTokens: 20, WallTimeSeconds: 1}
			switch kind {
			case "request-cap":
				config.MaxRequests = 0
			case "token-cap":
				config.MaxTokens = 9
			case "reserves-only":
				config.ValidationReserve = 80
				config.ReportingReserve = 20
			}
			run, err := s.StartBudget(ctx, sha, []TaskInput{{ID: "hunt", Stage: "hunt", InputSHA: sha, Paid: true}}, config)
			if err != nil {
				t.Fatal(err)
			}
			bound := request(t, s, "one", 10)
			switch kind {
			case "deadline":
				s.now = func() time.Time { return time.Unix(0, run.CreatedAt).Add(time.Second) }
			case "unknown-price":
				bound.PricingSHA = sha
			case "expired-price":
				s.now = func() time.Time { return time.Unix(0, run.CreatedAt).Add(2 * time.Hour) }
			case "changed-route":
				bound.Provider = "another-provider"
			case "underpriced":
				bound.MaxCost = 1
			}
			if _, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, bound); err == nil {
				t.Fatal("invalid request admitted")
			}
			snapshot, err := s.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Attempts) != 0 || snapshot.Tasks[0].Status != "pending" || len(snapshot.Budget.Reservations) != 0 {
				t.Fatal("failed admission partially committed")
			}
		})
	}
}

func TestBudgetConfigurationAndReservationIdempotency(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"tekmerion-budget-1","currency":"USD","limit_usd":1}`,
		`{"schema_version":"tekmerion-budget-1","currency":"USD","limit_usd":"1","validation_reserve_usd":"2"}`,
		`{"schema_version":"tekmerion-budget-1","currency":"USD","limit_usd":"1","unknown":true}`,
		`{"schema_version":"tekmerion-budget-1","currency":"USD","limit_usd":"1","limit_usd":"2"}`,
	} {
		if _, err := ParseBudget([]byte(raw)); err == nil {
			t.Fatalf("bad config accepted: %s", raw)
		}
	}
	s, _ := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 100, 0, 0, "hunt")
	bound := request(t, s, "one", 10)
	claim, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, bound)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveRequest(ctx, *claim, bound); err != nil {
		t.Fatal(err)
	}
	if accounting(t, s).Requests != 1 {
		t.Fatal("lost admission acknowledgement double-reserved money")
	}
	bound.Model = "changed"
	if err := s.ReserveRequest(ctx, *claim, bound); !errors.Is(err, ErrConflict) {
		t.Fatalf("request identity reused for a new model: %v", err)
	}
	for _, query := range []string{"UPDATE budgets SET limit_usd=200", "DELETE FROM reservations", "UPDATE reservations SET max_usd=0"} {
		if _, err := s.db.Exec(query); err == nil {
			t.Fatalf("accounting rewritten: %s", query)
		}
	}
}

func TestVersionOneMigrationPreservesFixtureHistory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "artifacts"), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"legacy":"fixture"}`)
	sha := digest(raw)
	if err := os.WriteFile(filepath.Join(dir, "artifacts", sha[7:]), raw, 0400); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO artifacts VALUES(?,?,?)", []any{sha, len(raw), "application/json"}},
		{"INSERT INTO runs VALUES('legacy',?,'running',1)", []any{sha}},
		{"INSERT INTO tasks(run_id,id,stage,input_sha,status) VALUES('legacy','one','fixture',?,'pending')", []any{sha}},
		{"INSERT INTO attempts VALUES('legacy-token','legacy','one',1,'old-worker',1)", nil},
		{"INSERT INTO attempt_results VALUES('legacy-token','interrupted',NULL,'legacy interruption',2)", nil},
	} {
		if _, err := db.Exec(stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Schema != SchemaVersion || snap.Run.ID != "legacy" || snap.Tasks[0].Paid || snap.Budget != nil {
		t.Fatalf("migration changed legacy input: %+v", snap)
	}
	if len(snap.Attempts) != 1 || snap.Attempts[0].Token != "legacy-token" || snap.Attempts[0].Outcome != "interrupted" {
		t.Fatal("migration lost prior attempt history")
	}
	if _, err := s.Get(ctx, sha); err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, "legacy", "one", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Number != 2 {
		t.Fatal("migration reset retry numbering")
	}
	if err := s.Finish(ctx, *claim, "completed", sha, ""); err != nil {
		t.Fatal(err)
	}
}

func TestProviderChargeRoundingAndNegativeAvailabilityJSON(t *testing.T) {
	for input, want := range map[string]Money{"0": 0, "0.0000000000": 0, "0.0000000001": 1, "0.1234567890": 123456789, "0.1234567891": 123456790} {
		got, err := ParseCharge(input)
		if err != nil || got != want {
			t.Fatalf("%s: %s %v", input, got, err)
		}
	}
	if _, err := ParseCharge("9223372036.8547758071"); err == nil {
		t.Fatal("rounded charge overflow accepted")
	}
	for _, amount := range []Money{-1, -Dollar, Money(math.MinInt64)} {
		raw, _ := json.Marshal(amount)
		var back Money
		if err := json.Unmarshal(raw, &back); err != nil || back != amount {
			t.Fatalf("signed money roundtrip: %s %v", raw, err)
		}
	}
	s, _ := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 10, 0, 0, "hunt")
	if _, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, request(t, s, "one", 10)); err != nil {
		t.Fatal(err)
	}
	evidence := put(t, s, `{"cost":"0.000000015"}`)
	if err := s.Settle(ctx, run.ID, "one", "provider:one", 15, nil, evidence); err != nil {
		t.Fatal(err)
	}
	snap := accounting(t, s)
	if snap.Available != -5 || snap.UnsettledRequests != 0 {
		t.Fatalf("overrun hidden: %+v", snap)
	}
	raw, _ := json.Marshal(snap)
	var back BudgetSnapshot
	if err := json.Unmarshal(raw, &back); err != nil || back.Available != -5 {
		t.Fatalf("overrun report cannot be read: %s %v", raw, err)
	}
}

func TestOneProviderGenerationCannotSettleTwoRequests(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 100, 0, 0, "hunt")
	claim, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, request(t, s, "one", 10))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveRequest(ctx, *claim, request(t, s, "two", 10)); err != nil {
		t.Fatal(err)
	}
	evidence := put(t, s, `{"cost":0}`)
	if err := s.Settle(ctx, run.ID, "one", "provider:generation-1", 0, nil, evidence); err != nil {
		t.Fatal(err)
	}
	if err := s.Settle(ctx, run.ID, "two", "provider:generation-1", 0, nil, evidence); err == nil {
		t.Fatal("same generation released two reservations")
	}
	snap := accounting(t, s)
	if snap.Outstanding != 10 || snap.UnsettledRequests != 1 {
		t.Fatalf("duplicate generation consumed reservation: %+v", snap)
	}
}

func TestKnownZeroChargeDoesNotResetInvocationCap(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	sha := put(t, s, `{}`)
	config := BudgetConfig{Schema: BudgetSchema, Currency: "USD", Limit: 100, MaxRequests: 1, MaxTokens: 100, WallTimeSeconds: 3600}
	run, err := s.StartBudget(ctx, sha, []TaskInput{{ID: "hunt", Stage: "hunt", InputSHA: sha, Paid: true}}, config)
	if err != nil {
		t.Fatal(err)
	}
	first := request(t, s, "one", 0)
	claim, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, first)
	if err != nil {
		t.Fatal(err)
	}
	zeroTokens := int64(0)
	if err := s.Settle(ctx, run.ID, "one", "provider:one", 0, &zeroTokens, sha); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveRequest(ctx, *claim, request(t, s, "two", 0)); !errors.Is(err, ErrBudget) {
		t.Fatalf("zero charge reset invocation counter: %v", err)
	}
	snap := accounting(t, s)
	if snap.Requests != 1 || snap.Tokens != 0 || snap.Available != 100 {
		t.Fatalf("independent caps corrupted: %+v", snap)
	}
}

func TestReservationRejectsCorruptedRequestBeforeClaimCommit(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 100, 0, 0, "hunt")
	bound := request(t, s, "one", 10)
	path := filepath.Join(s.dir, "artifacts", bound.RequestSHA[7:])
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`corrupted`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, bound); err == nil {
		t.Fatal("corrupted prompt admitted")
	}
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Attempts) != 0 || snapshot.Budget.Requests != 0 {
		t.Fatal("corrupted prompt left a partial admission")
	}
}

func TestDispatchIsOneShotAcrossRestartAndLateSettlement(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	run := budgetRun(t, s, 100, 0, 0, "hunt")
	bound := request(t, s, "one", 10)
	claim, err := s.ClaimRequest(ctx, run.ID, "hunt", "worker", time.Minute, bound)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Dispatch(ctx, *claim, bound.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Dispatch(ctx, *claim, bound.ID); !errors.Is(err, ErrDispatched) {
		t.Fatalf("uncertain dispatch repeated: %v", err)
	}
	snap := accounting(t, reopened)
	if snap.Reservations[0].DispatchedAt == nil || snap.Outstanding != 10 {
		t.Fatal("crash lost dispatch/reservation")
	}
	evidence := put(t, reopened, `{"cost":0}`)
	if err := reopened.Settle(ctx, run.ID, bound.ID, "provider:receipt", 0, nil, evidence); err != nil {
		t.Fatal(err)
	}
}

func TestForecastHistoryIsAppendOnly(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	run := start(t, s)
	report, plan, prices := put(t, s, `{"estimate":1}`), put(t, s, `{"plan":1}`), put(t, s, `{"prices":1}`)
	if err := s.AddForecast(ctx, run.ID, report, plan, prices); err != nil {
		t.Fatal(err)
	}
	if err := s.AddForecast(ctx, run.ID, report, plan, prices); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Forecasts) != 1 || snap.Forecasts[0].PricingSHA != prices {
		t.Fatal("lost or duplicated forecast identity")
	}
	if err := s.AddForecast(ctx, run.ID, report, prices, plan); !errors.Is(err, ErrConflict) {
		t.Fatal("existing forecast silently rebound to new input")
	}
	if _, err := s.db.Exec("DELETE FROM forecasts"); err == nil {
		t.Fatal("forecast history mutable")
	}
}
