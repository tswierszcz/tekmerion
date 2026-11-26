package state

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func readBudget(ctx context.Context, tx *sql.Tx, runID string) (*BudgetSnapshot, error) {
	b := &BudgetSnapshot{Reservations: []Reservation{}, Uncertain: []UncertainCharge{}, Halts: []BudgetHalt{}}
	var created int64
	err := tx.QueryRowContext(ctx, `SELECT b.limit_usd,b.validation_usd,b.reporting_usd,b.max_requests,b.max_tokens,b.deadline,r.created_at FROM budgets b JOIN runs r ON r.id=b.run_id WHERE b.run_id=?`, runID).Scan(&b.Config.Limit, &b.Config.ValidationReserve, &b.Config.ReportingReserve, &b.Config.MaxRequests, &b.Config.MaxTokens, &b.Deadline, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.Config.Schema, b.Config.Currency = BudgetSchema, "USD"
	b.Config.WallTimeSeconds = (b.Deadline - created) / int64(time.Second)
	b.ValidationProtected, b.ReportingProtected = b.Config.ValidationReserve, b.Config.ReportingReserve
	rows, err := tx.QueryContext(ctx, `SELECT q.request_id,q.token,q.stage,q.model,q.provider,q.pricing_sha,q.request_sha,q.max_usd,q.max_tokens,q.protected_credit,q.created_at,c.cost_usd,c.actual_tokens,COALESCE(c.response_id,''),COALESCE(c.evidence_sha,''),c.recorded_at,d.dispatched_at FROM reservations q LEFT JOIN charges c ON c.run_id=q.run_id AND c.request_id=q.request_id LEFT JOIN dispatches d ON d.run_id=q.run_id AND d.request_id=q.request_id WHERE q.run_id=? ORDER BY q.request_id`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		r := Reservation{RunID: runID}
		var cost, tokens, recorded, dispatched sql.NullInt64
		if err := rows.Scan(&r.ID, &r.AttemptToken, &r.Stage, &r.Model, &r.Provider, &r.PricingSHA, &r.RequestSHA, &r.MaxCost, &r.MaxTokens, &r.ProtectedCredit, &r.CreatedAt, &cost, &tokens, &r.ResponseID, &r.EvidenceSHA, &recorded, &dispatched); err != nil {
			rows.Close()
			return nil, err
		}
		if cost.Valid {
			v := Money(cost.Int64)
			r.Charge = &v
		}
		if tokens.Valid {
			v := tokens.Int64
			r.ActualTokens = &v
		}
		if recorded.Valid {
			v := recorded.Int64
			r.RecordedAt = &v
		}
		if dispatched.Valid {
			v := dispatched.Int64
			r.DispatchedAt = &v
		}
		b.Reservations = append(b.Reservations, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, r := range b.Reservations {
		usedTokens := r.MaxTokens
		protectedUsed := r.ProtectedCredit
		if r.Charge == nil {
			b.UnsettledRequests++
			total, err := add64(int64(b.Outstanding), int64(r.MaxCost))
			if err != nil {
				return nil, err
			}
			b.Outstanding = Money(total)
		} else {
			total, err := add64(int64(b.Settled), int64(*r.Charge))
			if err != nil {
				return nil, err
			}
			b.Settled = Money(total)
			protectedUsed = min(r.ProtectedCredit, *r.Charge)
			if r.ActualTokens != nil {
				usedTokens = *r.ActualTokens
			}
		}
		if r.Stage == "validate" {
			b.ValidationProtected -= protectedUsed
		} else if r.Stage == "report" {
			b.ReportingProtected -= protectedUsed
		}
		total, err := add64(b.Tokens, usedTokens)
		if err != nil {
			return nil, err
		}
		b.Tokens = total
		b.Requests++
	}
	spent, err := add64(int64(b.Settled), int64(b.Outstanding))
	if err != nil {
		return nil, err
	}
	protected, err := add64(int64(b.ValidationProtected), int64(b.ReportingProtected))
	if err != nil {
		return nil, err
	}
	committed, err := add64(spent, protected)
	if err != nil {
		return nil, err
	}
	b.Available = b.Config.Limit - Money(committed)
	rows, err = tx.QueryContext(ctx, "SELECT request_id,observation_id,reason,evidence_sha,recorded_at FROM uncertain_charges WHERE run_id=? ORDER BY observation_id", runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u UncertainCharge
		if err := rows.Scan(&u.RequestID, &u.ObservationID, &u.Reason, &u.EvidenceSHA, &u.RecordedAt); err != nil {
			rows.Close()
			return nil, err
		}
		b.Uncertain = append(b.Uncertain, u)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT request_id,reason FROM budget_halts WHERE run_id=? ORDER BY request_id", runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h BudgetHalt
		if err := rows.Scan(&h.RequestID, &h.Reason); err != nil {
			rows.Close()
			return nil, err
		}
		b.Halts = append(b.Halts, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return b, nil
}
