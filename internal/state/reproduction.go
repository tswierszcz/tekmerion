package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Reproduction is the runtime axis for one candidate. It is independent of
// the defect, static reachability and novelty axes and never confirms a
// finding on its own.
type Reproduction struct {
	TaskID      string `json:"task_id"`
	CandidateID string `json:"candidate_id"`
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	PayloadSHA  string `json:"payload_sha256"`
}

// CommitReproduction records the assessment and completes its local task in
// one transaction. Identical redelivery is a no-op; a different one conflicts.
func (s *Store) CommitReproduction(ctx context.Context, c Claim, resultSHA string, r Reproduction) error {
	switch r.Outcome {
	case "reproduced", "not_reproduced", "inconclusive", "blocked":
	default:
		return fmt.Errorf("invalid reproduction outcome %q", r.Outcome)
	}
	if r.TaskID != c.TaskID || r.Reason == "" || r.CandidateID == "" || !hashPattern.MatchString(r.PayloadSHA) {
		return fmt.Errorf("invalid reproduction record")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var prior Reproduction
	err = tx.QueryRowContext(ctx, "SELECT task_id,candidate_id,outcome,reason,payload_sha FROM reproductions WHERE run_id=? AND task_id=?", c.RunID, c.TaskID).Scan(&prior.TaskID, &prior.CandidateID, &prior.Outcome, &prior.Reason, &prior.PayloadSHA)
	if err == nil {
		if prior == r {
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
	if stage != "assessment" || paid {
		return fmt.Errorf("reproduction requires a local assessment task")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO reproductions VALUES(?,?,?,?,?,?)", c.RunID, r.TaskID, r.CandidateID, r.Outcome, r.Reason, r.PayloadSHA); err != nil {
		return err
	}
	if err := s.finishTx(ctx, tx, c, "completed", resultSHA, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func readReproductions(ctx context.Context, tx *sql.Tx, snap *Snapshot) error {
	rows, err := tx.QueryContext(ctx, "SELECT task_id,candidate_id,outcome,reason,payload_sha FROM reproductions WHERE run_id=? ORDER BY task_id", snap.Run.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r Reproduction
		if err := rows.Scan(&r.TaskID, &r.CandidateID, &r.Outcome, &r.Reason, &r.PayloadSHA); err != nil {
			return err
		}
		snap.Reproductions = append(snap.Reproductions, r)
	}
	return rows.Err()
}
