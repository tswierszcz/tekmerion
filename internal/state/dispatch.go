package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrDispatched = errors.New("request already dispatched or uncertain; a retry needs a new reservation")

// Dispatch records a one-shot boundary BEFORE networking. If the process dies
// after this commit, the request remains uncertain and can never be sent again
// under the same reservation. This is local fencing, not upstream idempotency.
func (s *Store) Dispatch(ctx context.Context, c Claim, requestID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var token, status, runStatus string
	var until int64
	var bound RequestBound
	err = tx.QueryRowContext(ctx, `SELECT t.lease_token,t.lease_until,t.status,r.status,q.request_id,q.model,q.provider,q.pricing_sha,q.request_sha,q.max_usd,q.max_tokens FROM tasks t JOIN runs r ON r.id=t.run_id JOIN reservations q ON q.run_id=t.run_id AND q.token=t.lease_token WHERE t.run_id=? AND t.id=? AND q.request_id=?`, c.RunID, c.TaskID, requestID).Scan(&token, &until, &status, &runStatus, &bound.ID, &bound.Model, &bound.Provider, &bound.PricingSHA, &bound.RequestSHA, &bound.MaxCost, &bound.MaxTokens)
	if err != nil {
		return err
	}
	now := s.now().UnixNano()
	if token != c.Token || until <= now || status != "running" || runStatus != "running" {
		return ErrLease
	}
	var prior int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dispatches WHERE run_id=? AND request_id=?", c.RunID, requestID).Scan(&prior); err != nil {
		return err
	}
	if prior != 0 {
		return ErrDispatched
	}
	budget, err := readBudget(ctx, tx, c.RunID)
	if err != nil {
		return err
	}
	if budget == nil {
		return ErrBudget
	}
	if len(budget.Halts) > 0 {
		return ErrHalted
	}
	if now >= budget.Deadline {
		return ErrBudget
	}
	if err := s.checkPrice(ctx, tx, bound, now); err != nil {
		return err
	}
	var charges int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM charges WHERE run_id=? AND request_id=?", c.RunID, requestID).Scan(&charges); err != nil {
		return err
	}
	if charges != 0 {
		return fmt.Errorf("settled reservation cannot dispatch")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO dispatches VALUES(?,?,?)", c.RunID, requestID, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) HaltAdmission(ctx context.Context, runID, requestID, reason string) error {
	if reason == "" {
		return fmt.Errorf("admission halt needs a reason")
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO budget_halts VALUES(?,?,?) ON CONFLICT DO NOTHING", runID, requestID, reason)
	return err
}

type Forecast struct {
	ReportSHA  string `json:"report_sha256"`
	PlanSHA    string `json:"plan_sha256"`
	PricingSHA string `json:"pricing_sha256"`
	RecordedAt int64  `json:"recorded_at_unix_nano"`
}

func (s *Store) AddForecast(ctx context.Context, runID, reportSHA, planSHA, pricingSHA string) error {
	if !hashPattern.MatchString(reportSHA) || !hashPattern.MatchString(planSHA) || !hashPattern.MatchString(pricingSHA) {
		return fmt.Errorf("forecast needs saved input and report identities")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldPlan, oldPricing string
	err = tx.QueryRowContext(ctx, "SELECT plan_sha,pricing_sha FROM forecasts WHERE run_id=? AND report_sha=?", runID, reportSHA).Scan(&oldPlan, &oldPricing)
	if err == nil {
		if oldPlan == planSHA && oldPricing == pricingSHA {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO forecasts VALUES(?,?,?,?,?)", runID, reportSHA, planSHA, pricingSHA, s.now().UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}
