package pricing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/state"
)

func input(t *testing.T) ([]byte, []byte, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := "0.0000005"
	s := Snapshot{Schema: SnapshotSchema, Source: "synthetic:test", Currency: "USD", RetrievedAt: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), Routes: []Route{{Model: "test/model", Provider: "provider", Input: "0.000001", Output: "0.000002", Request: "0.001", CacheRead: &cache, Complete: true, ReasoningIncluded: true}}}
	p := Plan{Schema: PlanSchema, TargetIdentity: "fixture:pinned", Scope: "file confinement", Assumptions: []string{"candidate yield and request counts are supplied assumptions"}, Roles: []Role{{Stage: "hunt", Model: "test/model", Provider: "provider", Low: Scenario{1, 100, 10, 50}, Base: Scenario{2, 200, 20, 100}, High: Scenario{3, 300, 30, 150}, MaxRequests: 4, InputLimit: 400, OutputLimit: 40}}}
	a, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return a, b, now
}
func TestForecastAndMissBoundExact(t *testing.T) {
	p, s, now := input(t)
	estimate, err := Build(p, s, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if estimate.Forecast.Low == nil || *estimate.Forecast.Low != 1120000 || *estimate.Forecast.Base != 2480000 || *estimate.Forecast.High != 4080000 || *estimate.Maximum != 5920000 {
		t.Fatalf("incorrect exact forecast: %+v", estimate)
	}
	if *estimate.Roles[0].CacheSavings.Base != 100000 {
		t.Fatal("cache savings calculation")
	}
	if estimate.MaxRequests != 4 || estimate.MaxTokens != 1760 || estimate.PricingSHA != Hash(s) || estimate.PlanSHA != Hash(p) {
		t.Fatal("workload/provenance lost")
	}
	again, err := Build(p, s, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(estimate)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatal("non-deterministic estimate for supplied inputs/time")
	}
}
func TestStaleUnknownAndManualBounds(t *testing.T) {
	p, raw, now := input(t)
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	s.ValidUntil = now.Add(-time.Minute)
	s.RetrievedAt = now.Add(-2 * time.Hour)
	stale, _ := json.Marshal(s)
	e, err := Build(p, stale, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Maximum != nil || e.Forecast.Base != nil || e.PricingFresh {
		t.Fatal("stale prices treated as reliable")
	}
	manual := state.Money(10000000)
	until := now.Add(30 * time.Minute)
	s.Routes[0].ManualBound = &manual
	s.Routes[0].ManualValidUntil = &until
	manualRaw, _ := json.Marshal(s)
	e, err = Build(p, manualRaw, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Maximum == nil || *e.Maximum != 4*manual || e.Forecast.Base != nil || e.Roles[0].BoundSource != "explicit_manual_ceiling" {
		t.Fatal("manual conservative bound not distinguished from forecast")
	}
	s.Routes = nil
	unknown, _ := json.Marshal(s)
	e, err = Build(p, unknown, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Maximum != nil {
		t.Fatal("unknown route priced")
	}
}
func TestBudgetReservesAndOverflow(t *testing.T) {
	p, s, now := input(t)
	config := state.BudgetConfig{Schema: state.BudgetSchema, Currency: "USD", Limit: 10000000, ValidationReserve: 3000000, ReportingReserve: 2000000, MaxRequests: 10, MaxTokens: 10000, WallTimeSeconds: 3600}
	e, err := Build(p, s, now, &config)
	if err != nil {
		t.Fatal(err)
	}
	if e.BudgetFits == nil || *e.BudgetFits {
		t.Fatal("protected reserves omitted from workload affordability")
	}
	config.Limit = 11000000
	e, err = Build(p, s, now, &config)
	if err != nil {
		t.Fatal(err)
	}
	if !*e.BudgetFits {
		t.Fatal("affordable finite workload rejected")
	}
	var plan Plan
	json.Unmarshal(p, &plan)
	plan.Roles[0].MaxRequests = 1 << 62
	raw, _ := json.Marshal(plan)
	if _, err := Build(raw, s, now, nil); err == nil {
		t.Fatal("overflow accepted")
	}
}
func TestStrictInputsAndUnsupportedDimensions(t *testing.T) {
	p, s, now := input(t)
	duplicate := strings.Replace(string(p), `"schema_version":`, `"schema_version":"wrong","schema_version":`, 1)
	if _, err := ParsePlan([]byte(duplicate)); err == nil {
		t.Fatal("duplicate config key accepted")
	}
	var snapshot Snapshot
	json.Unmarshal(s, &snapshot)
	snapshot.Routes[0].ReasoningIncluded = false
	raw, _ := json.Marshal(snapshot)
	e, err := Build(p, raw, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Maximum != nil {
		t.Fatal("unbounded reasoning bill dimension accepted")
	}
	snapshot.Routes[0].ReasoningIncluded = true
	expensiveCache := "0.1"
	snapshot.Routes[0].CacheRead = &expensiveCache
	raw, _ = json.Marshal(snapshot)
	if _, err := Build(p, raw, now, nil); err == nil {
		t.Fatal("cache charge above miss ceiling accepted")
	}
	snapshot.Routes[0].CacheRead = nil
	snapshot.Routes[0].Input = "0.000000000001"
	snapshot.Routes[0].Output = "0"
	snapshot.Routes[0].Request = "0"
	raw, _ = json.Marshal(snapshot)
	parsed, err := ParseSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	cost, _, _, err := Bound(parsed, "test/model", "provider", 1, 1, now)
	if err != nil || cost != 1 {
		t.Fatalf("sub-nanodollar cost rounded down: %s %v", cost, err)
	}
}

func TestCacheWriteCeilingDoesNotDiscountAdmission(t *testing.T) {
	_, raw, now := input(t)
	snapshot, err := ParseSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	write := "0.000003"
	snapshot.Routes[0].CacheWrite = &write
	maximum, _, _, err := Bound(snapshot, "test/model", "provider", 100, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	// Request fee .001 + worst input .0003 + output .00002. The total
	// cache-write price replaces input pricing; it is not counted twice.
	if maximum != 1320000 {
		t.Fatalf("cache-write ceiling wrong: %s", maximum)
	}
}
