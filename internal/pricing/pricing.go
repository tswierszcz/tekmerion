// Package pricing estimates a finite workload from a supplied normalized price
// snapshot. It performs no metadata refresh or inference and uses exact money.
package pricing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/state"
)

const SnapshotSchema = "tekmerion-pricing-1"
const PlanSchema = "tekmerion-estimate-plan-1"
const EstimateSchema = "tekmerion-estimate-1"

type Route struct {
	Model             string       `json:"model"`
	Provider          string       `json:"provider"`
	Input             string       `json:"input_usd_per_token"`
	Output            string       `json:"output_usd_per_token"`
	Request           string       `json:"request_usd"`
	CacheRead         *string      `json:"cache_read_usd_per_token,omitempty"`
	CacheWrite        *string      `json:"cache_write_total_usd_per_token,omitempty"`
	Complete          bool         `json:"all_billable_dimensions_bounded"`
	ReasoningIncluded bool         `json:"reasoning_included_in_output"`
	ManualBound       *state.Money `json:"manual_request_bound_usd,omitempty"`
	ManualValidUntil  *time.Time   `json:"manual_bound_valid_until,omitempty"`
}
type Snapshot struct {
	Schema      string    `json:"schema_version"`
	Source      string    `json:"source"`
	Currency    string    `json:"currency"`
	RetrievedAt time.Time `json:"retrieved_at"`
	ValidUntil  time.Time `json:"valid_until"`
	Routes      []Route   `json:"routes"`
}
type Scenario struct {
	Requests    int64 `json:"requests"`
	Input       int64 `json:"input_tokens_per_request"`
	Output      int64 `json:"output_tokens_per_request"`
	CachedInput int64 `json:"cached_input_tokens_per_request"`
}
type Role struct {
	Stage       string   `json:"stage"`
	Model       string   `json:"model"`
	Provider    string   `json:"provider"`
	Low         Scenario `json:"low"`
	Base        Scenario `json:"base"`
	High        Scenario `json:"high"`
	MaxRequests int64    `json:"max_requests_including_retries"`
	InputLimit  int64    `json:"input_token_limit"`
	OutputLimit int64    `json:"output_token_limit"`
}
type Plan struct {
	Schema         string   `json:"schema_version"`
	TargetIdentity string   `json:"target_identity"`
	Scope          string   `json:"scope"`
	Assumptions    []string `json:"assumptions"`
	Roles          []Role   `json:"roles"`
}
type Range struct {
	Low  *state.Money `json:"low_usd"`
	Base *state.Money `json:"base_usd"`
	High *state.Money `json:"high_usd"`
}
type RoleEstimate struct {
	Role         Role         `json:"workload"`
	Forecast     Range        `json:"uncached_forecast"`
	CacheSavings Range        `json:"forecast_cache_savings"`
	Maximum      *state.Money `json:"admission_bound_usd"`
	BoundSource  string       `json:"bound_source,omitempty"`
	Gaps         []string     `json:"gaps"`
}
type Estimate struct {
	Budget        *state.BudgetConfig `json:"checked_budget,omitempty"`
	Schema        string              `json:"schema_version"`
	PricingSHA    string              `json:"pricing_sha256"`
	PlanSHA       string              `json:"plan_sha256"`
	GeneratedAt   time.Time           `json:"generated_at"`
	PricingFresh  bool                `json:"pricing_fresh"`
	PricingSource string              `json:"pricing_source"`
	RetrievedAt   time.Time           `json:"pricing_retrieved_at"`
	ValidUntil    time.Time           `json:"pricing_valid_until"`
	Plan          Plan                `json:"plan"`
	Roles         []RoleEstimate      `json:"roles"`
	Forecast      Range               `json:"uncached_forecast"`
	Maximum       *state.Money        `json:"admission_bound_usd"`
	MaxRequests   int64               `json:"max_requests"`
	MaxTokens     int64               `json:"max_tokens"`
	BudgetFits    *bool               `json:"configured_budget_fits"`
	Gaps          []string            `json:"gaps"`
}

func Hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var decimal = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

func rate(s string) (*big.Rat, error) {
	if len(s) > 128 || !decimal.MatchString(s) {
		return nil, fmt.Errorf("price must be a bounded nonnegative decimal string")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("invalid price")
	}
	return r, nil
}
func ceilUSD(value *big.Rat) (state.Money, error) {
	n := new(big.Rat).Mul(value, new(big.Rat).SetInt64(int64(state.Dollar)))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(n.Num(), n.Denom(), rem)
	if rem.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() || q.Sign() < 0 {
		return 0, fmt.Errorf("priced workload overflows fixed-point money")
	}
	return state.Money(q.Int64()), nil
}
func ParseSnapshot(raw []byte) (Snapshot, error) {
	var s Snapshot
	if err := jsonx.Decode(raw, &s, false); err != nil {
		return s, err
	}
	if s.Schema != SnapshotSchema || s.Currency != "USD" || s.Source == "" || s.RetrievedAt.IsZero() || !s.ValidUntil.After(s.RetrievedAt) {
		return s, fmt.Errorf("pricing snapshot needs schema, USD, source and a finite validity window")
	}
	seen := map[string]bool{}
	for _, r := range s.Routes {
		key := r.Model + "\x00" + r.Provider
		if r.Model == "" || r.Provider == "" || seen[key] {
			return s, fmt.Errorf("missing or duplicate price route")
		}
		seen[key] = true
		if r.Complete {
			for _, value := range []string{r.Input, r.Output, r.Request} {
				if _, err := rate(value); err != nil {
					return s, err
				}
			}
		}
		if r.CacheRead != nil {
			if _, err := rate(*r.CacheRead); err != nil {
				return s, err
			}
		}
		if r.CacheWrite != nil {
			if _, err := rate(*r.CacheWrite); err != nil {
				return s, err
			}
		}
		if r.ManualBound != nil && (*r.ManualBound < 0 || r.ManualValidUntil == nil || r.ManualValidUntil.IsZero()) {
			return s, fmt.Errorf("manual price ceiling needs nonnegative money and explicit validity")
		}
	}
	return s, nil
}
func ParsePlan(raw []byte) (Plan, error) {
	var p Plan
	if err := jsonx.Decode(raw, &p, false); err != nil {
		return p, err
	}
	if p.Schema != PlanSchema || p.TargetIdentity == "" || p.Scope == "" || len(p.Assumptions) == 0 || len(p.Roles) == 0 {
		return p, fmt.Errorf("estimate plan needs pinned target/scope, assumptions and roles")
	}
	seen := map[string]bool{}
	for _, r := range p.Roles {
		if (r.Stage != "recon" && r.Stage != "hunt" && r.Stage != "validate" && r.Stage != "report") || seen[r.Stage] || r.Model == "" || r.Provider == "" || r.MaxRequests <= 0 || r.InputLimit <= 0 || r.OutputLimit <= 0 {
			return p, fmt.Errorf("invalid or duplicate bounded role")
		}
		seen[r.Stage] = true
		previous := Scenario{}
		for _, sc := range []Scenario{r.Low, r.Base, r.High} {
			if sc.Requests < previous.Requests || sc.Input < previous.Input || sc.Output < previous.Output || sc.CachedInput < 0 || sc.CachedInput > sc.Input || sc.Requests > r.MaxRequests || sc.Input > r.InputLimit || sc.Output > r.OutputLimit {
				return p, fmt.Errorf("role scenarios must be nonnegative, ordered and within finite bounds")
			}
			previous = sc
		}
	}
	return p, nil
}
func findRoute(s Snapshot, model, provider string) (Route, bool) {
	for _, r := range s.Routes {
		if r.Model == model && r.Provider == provider {
			return r, true
		}
	}
	return Route{}, false
}
func fresh(s Snapshot, now time.Time) bool {
	return !now.Before(s.RetrievedAt) && now.Before(s.ValidUntil)
}
func priced(r Route, input, output, cached, requests int64, cache bool) (state.Money, error) {
	in, err := rate(r.Input)
	if err != nil {
		return 0, err
	}
	out, err := rate(r.Output)
	if err != nil {
		return 0, err
	}
	perRequest, err := rate(r.Request)
	if err != nil {
		return 0, err
	}
	total := new(big.Rat).Add(new(big.Rat).Mul(in, new(big.Rat).SetInt64(input)), new(big.Rat).Mul(out, new(big.Rat).SetInt64(output)))
	total.Add(total, perRequest)
	if cache && r.CacheRead != nil {
		cachedRate, err := rate(*r.CacheRead)
		if err != nil {
			return 0, err
		}
		if cachedRate.Cmp(in) > 0 {
			return 0, fmt.Errorf("cache rate exceeds uncached input rate; no safe miss bound")
		}
		saving := new(big.Rat).Mul(new(big.Rat).Sub(in, cachedRate), new(big.Rat).SetInt64(cached))
		total.Sub(total, saving)
	}
	total.Mul(total, new(big.Rat).SetInt64(requests))
	return ceilUSD(total)
}

// Bound returns a cache-miss ceiling. Incomplete or stale rates require a
// separately recorded, still-valid manual conservative ceiling.
func Bound(s Snapshot, model, provider string, input, output int64, now time.Time) (state.Money, time.Time, string, error) {
	if input <= 0 || output <= 0 {
		return 0, time.Time{}, "", fmt.Errorf("finite positive input/output caps required")
	}
	r, ok := findRoute(s, model, provider)
	if !ok {
		return 0, time.Time{}, "", fmt.Errorf("route has no price evidence")
	}
	if fresh(s, now) && r.Complete && r.ReasoningIncluded {
		if r.CacheRead != nil {
			cache, _ := rate(*r.CacheRead)
			uncached, _ := rate(r.Input)
			if cache.Cmp(uncached) > 0 {
				return 0, time.Time{}, "", fmt.Errorf("cache price exceeds declared input ceiling")
			}
		}
		// A normalized cache-write rate is the total input-token price,
		// including ordinary input billing, rather than an additive subtotal.
		if r.CacheWrite != nil {
			write, _ := rate(*r.CacheWrite)
			normal, _ := rate(r.Input)
			if write.Cmp(normal) > 0 {
				r.Input = *r.CacheWrite
			}
		}
		cost, err := priced(r, input, output, 0, 1, false)
		return cost, s.ValidUntil, "snapshot_cache_miss", err
	}
	if r.ManualBound != nil && r.ManualValidUntil != nil && now.Before(*r.ManualValidUntil) {
		return *r.ManualBound, *r.ManualValidUntil, "explicit_manual_ceiling", nil
	}
	return 0, time.Time{}, "", fmt.Errorf("fresh complete route pricing unavailable; explicit conservative ceiling required")
}
func Build(planRaw, pricingRaw []byte, now time.Time, budget *state.BudgetConfig) (*Estimate, error) {
	p, err := ParsePlan(planRaw)
	if err != nil {
		return nil, err
	}
	s, err := ParseSnapshot(pricingRaw)
	if err != nil {
		return nil, err
	}
	if budget != nil {
		if err := budget.Validate(); err != nil {
			return nil, err
		}
	}
	e := &Estimate{Budget: budget, Schema: EstimateSchema, PricingSHA: Hash(pricingRaw), PlanSHA: Hash(planRaw), GeneratedAt: now.UTC(), PricingFresh: fresh(s, now), PricingSource: s.Source, RetrievedAt: s.RetrievedAt, ValidUntil: s.ValidUntil, Plan: p, Roles: []RoleEstimate{}, Gaps: []string{}}
	totals := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	maximum := big.NewInt(0)
	maxRequests, maxTokens := big.NewInt(0), big.NewInt(0)
	allForecast, allBounds := true, true
	for _, role := range p.Roles {
		re := RoleEstimate{Role: role, Gaps: []string{}}
		route, found := findRoute(s, role.Model, role.Provider)
		forecast := []*state.Money{nil, nil, nil}
		savings := []*state.Money{nil, nil, nil}
		if found && e.PricingFresh && route.Complete && route.ReasoningIncluded {
			for i, sc := range []Scenario{role.Low, role.Base, role.High} {
				cost, err := priced(route, sc.Input, sc.Output, 0, sc.Requests, false)
				if err != nil {
					return nil, err
				}
				forecast[i] = &cost
				totals[i].Add(totals[i], big.NewInt(int64(cost)))
				if route.CacheRead != nil {
					discounted, err := priced(route, sc.Input, sc.Output, sc.CachedInput, sc.Requests, true)
					if err != nil {
						return nil, err
					}
					saved := cost - discounted
					savings[i] = &saved
				}
			}
		} else {
			allForecast = false
			re.Gaps = append(re.Gaps, "scenario forecast unavailable from fresh complete rates")
		}
		re.Forecast = Range{forecast[0], forecast[1], forecast[2]}
		re.CacheSavings = Range{savings[0], savings[1], savings[2]}
		perRequest, _, source, boundErr := Bound(s, role.Model, role.Provider, role.InputLimit, role.OutputLimit, now)
		if boundErr != nil {
			allBounds = false
			re.Gaps = append(re.Gaps, boundErr.Error())
		} else {
			maxCost := new(big.Int).Mul(big.NewInt(int64(perRequest)), big.NewInt(role.MaxRequests))
			if !maxCost.IsInt64() {
				return nil, fmt.Errorf("workload cost overflow")
			}
			value := state.Money(maxCost.Int64())
			re.Maximum = &value
			re.BoundSource = source
			maximum.Add(maximum, maxCost)
		}
		maxRequests.Add(maxRequests, big.NewInt(role.MaxRequests))
		tokens := new(big.Int).Add(big.NewInt(role.InputLimit), big.NewInt(role.OutputLimit))
		tokens.Mul(tokens, big.NewInt(role.MaxRequests))
		maxTokens.Add(maxTokens, tokens)
		e.Roles = append(e.Roles, re)
	}
	if !maxRequests.IsInt64() || !maxTokens.IsInt64() || !maximum.IsInt64() {
		return nil, fmt.Errorf("finite workload counters overflow")
	}
	e.MaxRequests, e.MaxTokens = maxRequests.Int64(), maxTokens.Int64()
	if allForecast {
		values := []state.Money{}
		for _, total := range totals {
			if !total.IsInt64() {
				return nil, fmt.Errorf("forecast overflow")
			}
			values = append(values, state.Money(total.Int64()))
		}
		e.Forecast = Range{&values[0], &values[1], &values[2]}
	}
	if allBounds {
		value := state.Money(maximum.Int64())
		e.Maximum = &value
	}
	if !e.PricingFresh {
		e.Gaps = append(e.Gaps, "pricing snapshot is stale or future-dated")
	}
	if budget != nil && e.Maximum != nil {
		// Unused protected reserves stay unavailable to other stages.
		validation, report := state.Money(0), state.Money(0)
		for _, r := range e.Roles {
			if r.Role.Stage == "validate" {
				validation = *r.Maximum
			}
			if r.Role.Stage == "report" {
				report = *r.Maximum
			}
		}
		need := new(big.Int).Set(maximum)
		need.Add(need, big.NewInt(int64(max(0, budget.ValidationReserve-validation))))
		need.Add(need, big.NewInt(int64(max(0, budget.ReportingReserve-report))))
		fits := need.Cmp(big.NewInt(int64(budget.Limit))) <= 0 && e.MaxRequests <= budget.MaxRequests && e.MaxTokens <= budget.MaxTokens
		e.BudgetFits = &fits
		if !fits {
			e.Gaps = append(e.Gaps, "finite workload plus protected reserves exceeds a configured money/request/token cap")
		}
	}
	e.Gaps = append(e.Gaps, "scenario forecasts are assumptions, not confidence intervals; local compute, credit fees and taxes are excluded")
	return e, nil
}
