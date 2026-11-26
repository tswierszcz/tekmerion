package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Decision is a versioned mapping of independent axes (verifier review,
// reproduction, fresh replay) to a report label. It is derived by rules, not
// chosen by a model, and is immutable once committed.
type Decision struct {
	TaskID      string `json:"task_id"`
	CandidateID string `json:"candidate_id"`
	Label       string `json:"label"`
	Verifier    string `json:"verifier"`
	Rules       string `json:"rules"`
	Reason      string `json:"reason"`
	PayloadSHA  string `json:"payload_sha256"`
}

// CommitDecision records the decision and completes its local task atomically.
func (s *Store) CommitDecision(ctx context.Context, c Claim, resultSHA string, d Decision) error {
	switch d.Label {
	case "confirmed", "needs_validation", "rejected":
	default:
		return fmt.Errorf("invalid decision label %q", d.Label)
	}
	switch d.Verifier {
	case "supported", "refuted", "unresolved":
	default:
		return fmt.Errorf("invalid verifier decision %q", d.Verifier)
	}
	if d.TaskID != c.TaskID || d.CandidateID == "" || d.Rules == "" || d.Reason == "" || !hashPattern.MatchString(d.PayloadSHA) {
		return fmt.Errorf("invalid decision record")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var prior Decision
	err = tx.QueryRowContext(ctx, "SELECT task_id,candidate_id,label,verifier,rules,reason,payload_sha FROM decisions WHERE run_id=? AND task_id=?", c.RunID, c.TaskID).Scan(&prior.TaskID, &prior.CandidateID, &prior.Label, &prior.Verifier, &prior.Rules, &prior.Reason, &prior.PayloadSHA)
	if err == nil {
		if prior == d {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var stage string
	var paid bool
	if err := tx.QueryRowContext(ctx, "SELECT stage,paid FROM tasks WHERE run_id=? AND id=?", c.RunID, c.TaskID).Scan(&stage, &paid); err != nil {
		return err
	}
	if stage != "decision" || paid {
		return fmt.Errorf("decision requires a local decision task")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?)", c.RunID, d.TaskID, d.CandidateID, d.Label, d.Verifier, d.Rules, d.Reason, d.PayloadSHA); err != nil {
		return err
	}
	if err := s.finishTx(ctx, tx, c, "completed", resultSHA, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func readDecisions(ctx context.Context, tx *sql.Tx, snap *Snapshot) error {
	rows, err := tx.QueryContext(ctx, "SELECT task_id,candidate_id,label,verifier,rules,reason,payload_sha FROM decisions WHERE run_id=? ORDER BY task_id", snap.Run.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.TaskID, &d.CandidateID, &d.Label, &d.Verifier, &d.Rules, &d.Reason, &d.PayloadSHA); err != nil {
			return err
		}
		snap.Decisions = append(snap.Decisions, d)
	}
	return rows.Err()
}
