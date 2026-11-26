package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type CoverageSeed struct {
	ID             string `json:"id"`
	Canonical      string `json:"canonical"`
	SourceIdentity string `json:"source_identity"`
	PayloadSHA     string `json:"payload_sha256"`
	Status         string `json:"status"`
	Reason         string `json:"reason"`
}
type CoverageUnit struct {
	CoverageSeed
	RunID  string `json:"run_id"`
	TaskID string `json:"producing_task_id"`
}

// CommitCoverage atomically commits an initial Recon projection and completes
// its local task. No unit is promoted to checked/candidate by this operation.
func (s *Store) CommitCoverage(ctx context.Context, c Claim, resultSHA string, seeds []CoverageSeed) error {
	sorted := append([]CoverageSeed{}, seeds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for i, seed := range sorted {
		if !hashPattern.MatchString(seed.ID) || digest([]byte(seed.Canonical)) != seed.ID || !hashPattern.MatchString(seed.SourceIdentity) || !hashPattern.MatchString(seed.PayloadSHA) {
			return fmt.Errorf("invalid canonical coverage/evidence identity")
		}
		if i > 0 && sorted[i-1].ID == seed.ID {
			return fmt.Errorf("duplicate/colliding canonical coverage identity")
		}
		if seed.Status != "planned" && seed.Status != "blocked" && seed.Status != "deferred" && seed.Status != "out_of_scope" {
			return fmt.Errorf("invalid initial coverage status")
		}
		if seed.Status != "planned" && seed.Reason == "" {
			return fmt.Errorf("initial coverage state requires a reason")
		}
	}
	raw, err := json.Marshal(sorted)
	if err != nil {
		return err
	}
	seedSHA := digest(raw)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var priorResult, priorSeeds string
	err = tx.QueryRowContext(ctx, "SELECT result_sha,seed_sha FROM coverage_batches WHERE run_id=? AND task_id=?", c.RunID, c.TaskID).Scan(&priorResult, &priorSeeds)
	if err == nil {
		if priorResult == resultSHA && priorSeeds == seedSHA {
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
	if stage != "coverage" || paid {
		return fmt.Errorf("coverage projection requires its local coverage task")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO coverage_batches VALUES(?,?,?,?,?)", c.RunID, c.TaskID, c.Token, resultSHA, seedSHA); err != nil {
		return err
	}
	for _, seed := range sorted {
		if _, err := tx.ExecContext(ctx, "INSERT INTO coverage_units VALUES(?,?,?,?,?,?,?,?)", c.RunID, seed.ID, seed.Canonical, seed.SourceIdentity, seed.PayloadSHA, seed.Status, seed.Reason, c.TaskID); err != nil {
			return err
		}
	}
	if err := s.finishTx(ctx, tx, c, "completed", resultSHA, ""); err != nil {
		return err
	}
	return tx.Commit()
}
