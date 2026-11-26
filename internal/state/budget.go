package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

const BudgetSchema = "tekmerion-budget-1"

var (
	ErrBudget = errors.New("request exceeds available budget")
	ErrHalted = errors.New("paid admission halted after a bound discrepancy")
)

type BudgetConfig struct {
	Schema            string `json:"schema_version"`
	Currency          string `json:"currency"`
	Limit             Money  `json:"limit_usd"`
	ValidationReserve Money  `json:"validation_reserve_usd"`
	ReportingReserve  Money  `json:"reporting_reserve_usd"`
	MaxRequests       int64  `json:"max_requests"`
	MaxTokens         int64  `json:"max_tokens"`
	WallTimeSeconds   int64  `json:"wall_time_seconds"`
}

func (c BudgetConfig) Validate() error {
	if c.Schema != BudgetSchema || c.Currency != "USD" {
		return fmt.Errorf("budget requires %s and currency USD", BudgetSchema)
	}
	if c.Limit < 0 || c.ValidationReserve < 0 || c.ReportingReserve < 0 || c.MaxRequests < 0 || c.MaxTokens < 0 || c.WallTimeSeconds < 0 || c.WallTimeSeconds > int64((365*24*time.Hour)/time.Second) {
		return fmt.Errorf("invalid nonnegative budget limits (wall time at most one year)")
	}
	reserves, err := add64(int64(c.ValidationReserve), int64(c.ReportingReserve))
	if err != nil {
		return err
	}
	if Money(reserves) > c.Limit {
		return fmt.Errorf("budget is smaller than protected reserves")
	}
	if c.MaxRequests > 0 && (c.MaxTokens == 0 || c.WallTimeSeconds == 0) {
		return fmt.Errorf("request admission needs finite token and wall-time limits")
	}
	return nil
}
func paidStage(stage string) bool {
	return stage == "recon" || stage == "hunt" || stage == "validate" || stage == "report"
}

type RequestBound struct {
	ID         string `json:"request_id"`
	Model      string `json:"model"`
	Provider   string `json:"provider"`
	PricingSHA string `json:"pricing_sha256"`
	RequestSHA string `json:"request_sha256"`
	MaxCost    Money  `json:"max_cost_usd"`
	MaxTokens  int64  `json:"max_tokens"`
}

func (r RequestBound) validate() error {
	if r.ID == "" || r.Model == "" || r.Provider == "" || !hashPattern.MatchString(r.PricingSHA) || !hashPattern.MatchString(r.RequestSHA) || r.MaxCost < 0 || r.MaxTokens <= 0 {
		return fmt.Errorf("request needs identity, exact route, saved pricing/request evidence and finite nonnegative cost/positive token bounds")
	}
	return nil
}

type Reservation struct {
	RequestBound
	RunID           string `json:"run_id"`
	AttemptToken    string `json:"attempt_token"`
	Stage           string `json:"stage"`
	ProtectedCredit Money  `json:"protected_credit_usd"`
	CreatedAt       int64  `json:"created_at_unix_nano"`
	Charge          *Money `json:"reported_cost_usd"`
	ActualTokens    *int64 `json:"reported_tokens"`
	ResponseID      string `json:"response_id,omitempty"`
	EvidenceSHA     string `json:"charge_evidence_sha256,omitempty"`
	DispatchedAt    *int64 `json:"dispatched_at_unix_nano,omitempty"`
	RecordedAt      *int64 `json:"charge_recorded_at_unix_nano,omitempty"`
}
type UncertainCharge struct {
	RequestID     string `json:"request_id"`
	ObservationID string `json:"observation_id"`
	Reason        string `json:"reason"`
	EvidenceSHA   string `json:"evidence_sha256"`
	RecordedAt    int64  `json:"recorded_at_unix_nano"`
}
type BudgetHalt struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason"`
}
type BudgetSnapshot struct {
	Config              BudgetConfig      `json:"config"`
	Deadline            int64             `json:"deadline_unix_nano"`
	Settled             Money             `json:"settled_usd"`
	Outstanding         Money             `json:"outstanding_reservations_usd"`
	ValidationProtected Money             `json:"validation_protected_usd"`
	ReportingProtected  Money             `json:"reporting_protected_usd"`
	Available           Money             `json:"available_usd"`
	Requests            int64             `json:"requests_reserved"`
	UnsettledRequests   int64             `json:"unsettled_requests"`
	Tokens              int64             `json:"tokens_accounted"`
	Reservations        []Reservation     `json:"reservations"`
	Uncertain           []UncertainCharge `json:"uncertain_charge_observations"`
	Halts               []BudgetHalt      `json:"admission_halts"`
}

// ClaimRequest atomically acquires a paid task AND reserves its next request.
// On budget rejection neither an attempt nor a new lease is committed.
func (s *Store) ClaimRequest(ctx context.Context, runID, taskID, worker string, ttl time.Duration, bound RequestBound) (*Claim, error) {
	if worker == "" || ttl <= 0 {
		return nil, fmt.Errorf("worker and positive lease duration required")
	}
	if err := bound.validate(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := s.claimTx(ctx, tx, runID, taskID, worker, ttl, true)
	if err != nil {
		return nil, err
	}
	if err := s.reserveTx(ctx, tx, *c, bound); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return c, nil
}

// ReserveRequest admits subsequent tool-loop requests under the same live task
// lease. A timeout/retry needs a distinct request id and its own reservation.
func (s *Store) ReserveRequest(ctx context.Context, c Claim, bound RequestBound) error {
	if err := bound.validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.reserveTx(ctx, tx, c, bound); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) reserveTx(ctx context.Context, tx *sql.Tx, c Claim, bound RequestBound) error {
	var stage, status, runStatus string
	var token sql.NullString
	var until sql.NullInt64
	var paid bool
	if err := tx.QueryRowContext(ctx, `SELECT t.stage,t.status,t.lease_token,t.lease_until,t.paid,r.status FROM tasks t JOIN runs r ON t.run_id=r.id WHERE t.run_id=? AND t.id=?`, c.RunID, c.TaskID).Scan(&stage, &status, &token, &until, &paid, &runStatus); err != nil {
		return err
	}
	now := s.now().UnixNano()
	if status != "running" || runStatus != "running" || !token.Valid || token.String != c.Token || until.Int64 <= now {
		return ErrLease
	}
	if !paid || !paidStage(stage) {
		return fmt.Errorf("paid admission requires a paid research task")
	}
	// Retrying an admission whose local acknowledgement was lost is idempotent,
	// but can never hand an old reservation to a different lease or route.
	var previous RequestBound
	var previousToken string
	err := tx.QueryRowContext(ctx, "SELECT token,request_id,model,provider,pricing_sha,request_sha,max_usd,max_tokens FROM reservations WHERE run_id=? AND request_id=?", c.RunID, bound.ID).Scan(&previousToken, &previous.ID, &previous.Model, &previous.Provider, &previous.PricingSHA, &previous.RequestSHA, &previous.MaxCost, &previous.MaxTokens)
	if err == nil {
		if previousToken == c.Token && previous == bound {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	requestArtifact := &Artifact{SHA: bound.RequestSHA}
	if err := tx.QueryRowContext(ctx, "SELECT size,media_type FROM artifacts WHERE sha=?", bound.RequestSHA).Scan(&requestArtifact.Size, &requestArtifact.MediaType); err != nil {
		return err
	}
	if _, err := readArtifact(filepath.Join(s.dir, "artifacts", bound.RequestSHA[7:]), requestArtifact); err != nil {
		return err
	}
	if err := s.checkPrice(ctx, tx, bound, now); err != nil {
		return err
	}
	budget, err := readBudget(ctx, tx, c.RunID)
	if err != nil {
		return err
	}
	if budget == nil {
		return fmt.Errorf("paid admission requires a configured budget")
	}
	if len(budget.Halts) > 0 {
		return ErrHalted
	}
	if now >= budget.Deadline {
		return fmt.Errorf("%w: wall-time limit reached", ErrBudget)
	}
	if budget.Requests >= budget.Config.MaxRequests {
		return fmt.Errorf("%w: request limit reached", ErrBudget)
	}
	tokens, err := add64(budget.Tokens, bound.MaxTokens)
	if err != nil {
		return err
	}
	if tokens > budget.Config.MaxTokens {
		return fmt.Errorf("%w: token limit reached", ErrBudget)
	}
	credit := Money(0)
	if stage == "validate" {
		credit = min(bound.MaxCost, budget.ValidationProtected)
	} else if stage == "report" {
		credit = min(bound.MaxCost, budget.ReportingProtected)
	}
	if bound.MaxCost-credit > budget.Available {
		return fmt.Errorf("%w: request needs %s USD beyond protected credit; available %s USD", ErrBudget, bound.MaxCost-credit, budget.Available)
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", c.RunID, bound.ID, c.Token, stage, bound.Model, bound.Provider, bound.PricingSHA, bound.RequestSHA, bound.MaxCost, bound.MaxTokens, credit, now)
	return err
}

// Settle records an authoritative reported cost exactly once. Zero is a known
// charge. A missing charge must use ObserveUncertain and keeps money reserved.
// Reconciliation deliberately does not require a current task lease: a late
// provider receipt can settle an earlier attempt after a restart or retry.
func (s *Store) Settle(ctx context.Context, runID, requestID, responseID string, cost Money, tokens *int64, evidenceSHA string) error {
	if responseID == "" || cost < 0 || tokens != nil && *tokens < 0 || !hashPattern.MatchString(evidenceSHA) {
		return fmt.Errorf("settlement requires response identity, known nonnegative cost/usage and saved evidence")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldResponse, oldEvidence string
	var oldCost Money
	var oldTokens sql.NullInt64
	err = tx.QueryRowContext(ctx, "SELECT response_id,cost_usd,actual_tokens,evidence_sha FROM charges WHERE run_id=? AND request_id=?", runID, requestID).Scan(&oldResponse, &oldCost, &oldTokens, &oldEvidence)
	if err == nil {
		sameTokens := !oldTokens.Valid && tokens == nil || oldTokens.Valid && tokens != nil && oldTokens.Int64 == *tokens
		if oldResponse == responseID && oldCost == cost && sameTokens && oldEvidence == evidenceSHA {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var maximum Money
	var maxTokens int64
	if err := tx.QueryRowContext(ctx, "SELECT max_usd,max_tokens FROM reservations WHERE run_id=? AND request_id=?", runID, requestID).Scan(&maximum, &maxTokens); err != nil {
		return err
	}
	var reportedTokens any
	if tokens != nil {
		reportedTokens = *tokens
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO charges VALUES(?,?,?,?,?,?,?)", runID, requestID, responseID, cost, reportedTokens, evidenceSHA, s.now().UnixNano()); err != nil {
		return err
	}
	if cost > maximum || tokens != nil && *tokens > maxTokens {
		reason := fmt.Sprintf("reported cost %s / tokens %v exceeded reserved cost %s / tokens %d", cost, tokensValue(tokens), maximum, maxTokens)
		if _, err := tx.ExecContext(ctx, "INSERT INTO budget_halts VALUES(?,?,?) ON CONFLICT DO NOTHING", runID, requestID, reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func tokensValue(tokens *int64) any {
	if tokens == nil {
		return "unknown"
	}
	return *tokens
}

func (s *Store) ObserveUncertain(ctx context.Context, runID, requestID, observationID, reason, evidenceSHA string) error {
	if observationID == "" || reason == "" || !hashPattern.MatchString(evidenceSHA) {
		return fmt.Errorf("uncertain charge needs observation identity, reason and evidence")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldRequest, oldReason, oldEvidence string
	err = tx.QueryRowContext(ctx, "SELECT request_id,reason,evidence_sha FROM uncertain_charges WHERE run_id=? AND observation_id=?", runID, observationID).Scan(&oldRequest, &oldReason, &oldEvidence)
	if err == nil {
		if oldRequest == requestID && oldReason == reason && oldEvidence == evidenceSHA {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO uncertain_charges VALUES(?,?,?,?,?,?)", runID, requestID, observationID, reason, evidenceSHA, s.now().UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}
