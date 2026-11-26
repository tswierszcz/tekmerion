package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Candidate identities describe exact source mechanisms, not confirmed defects.
// Every entry path retains its own occurrence payload and independent static assessment.
type Candidate struct {
	ID             string `json:"id"`
	Canonical      string `json:"canonical"`
	SourceIdentity string `json:"source_identity"`
	PayloadSHA     string `json:"payload_sha256"`
}
type CandidateOccurrence struct {
	CandidateID string `json:"candidate_id"`
	UnitID      string `json:"unit_id"`
	TaskID      string `json:"task_id"`
	PayloadSHA  string `json:"payload_sha256"`
}
type CoverageEvent struct {
	UnitID     string `json:"unit_id"`
	TaskID     string `json:"task_id"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	PayloadSHA string `json:"payload_sha256"`
}
type HuntCommit struct {
	Candidates  []Candidate           `json:"candidates"`
	Occurrences []CandidateOccurrence `json:"occurrences"`
	Event       CoverageEvent         `json:"event"`
}

// CommitHunt publishes one bounded unit's evidence and finishes the local triage
// task in one transaction. Initial coverage is never rewritten.
func (s *Store) CommitHunt(ctx context.Context, c Claim, resultSHA string, in HuntCommit) error {
	sort.Slice(in.Candidates, func(i, j int) bool { return in.Candidates[i].ID < in.Candidates[j].ID })
	sort.Slice(in.Occurrences, func(i, j int) bool { return in.Occurrences[i].CandidateID < in.Occurrences[j].CandidateID })
	e := in.Event
	if e.TaskID != c.TaskID || e.Reason == "" || !hashPattern.MatchString(e.PayloadSHA) {
		return fmt.Errorf("invalid Hunt event")
	}
	if e.Status != "checked" && e.Status != "candidate" && e.Status != "blocked" && e.Status != "deferred" {
		return fmt.Errorf("invalid Hunt coverage state")
	}
	if (e.Status == "candidate") != (len(in.Candidates) > 0) || len(in.Candidates) != len(in.Occurrences) {
		return fmt.Errorf("candidate coverage needs its occurrences")
	}
	for i, v := range in.Candidates {
		if digest([]byte(v.Canonical)) != v.ID || !hashPattern.MatchString(v.SourceIdentity) || !hashPattern.MatchString(v.PayloadSHA) || (i > 0 && in.Candidates[i-1].ID == v.ID) {
			return fmt.Errorf("invalid candidate canonical identity")
		}
		o := in.Occurrences[i]
		if o.CandidateID != v.ID || o.UnitID != e.UnitID || o.TaskID != c.TaskID || !hashPattern.MatchString(o.PayloadSHA) {
			return fmt.Errorf("invalid candidate occurrence")
		}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	seedSHA := digest(raw)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var prior, seed string
	err = tx.QueryRowContext(ctx, "SELECT result_sha,seed_sha FROM hunt_batches WHERE run_id=? AND task_id=?", c.RunID, c.TaskID).Scan(&prior, &seed)
	if err == nil {
		if prior == resultSHA && seed == seedSHA {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var stage, status, source string
	var paid bool
	if err = tx.QueryRowContext(ctx, "SELECT stage,paid FROM tasks WHERE run_id=? AND id=?", c.RunID, c.TaskID).Scan(&stage, &paid); err != nil {
		return err
	}
	if stage != "triage" || paid {
		return fmt.Errorf("Hunt projection requires local triage task")
	}
	if err = tx.QueryRowContext(ctx, "SELECT status,source_identity FROM coverage_units WHERE run_id=? AND id=?", c.RunID, e.UnitID).Scan(&status, &source); err != nil {
		return err
	}
	if status != "planned" {
		return fmt.Errorf("Hunt only projects planned units")
	}
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM coverage_events WHERE run_id=? AND unit_id=?", c.RunID, e.UnitID).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO hunt_batches VALUES(?,?,?,?)", c.RunID, c.TaskID, resultSHA, seedSHA); err != nil {
		return err
	}
	for i, v := range in.Candidates {
		if v.SourceIdentity != source {
			return fmt.Errorf("candidate source identity differs from coverage")
		}
		var canonical, identity string
		err = tx.QueryRowContext(ctx, "SELECT canonical,source_identity FROM candidates WHERE run_id=? AND id=?", c.RunID, v.ID).Scan(&canonical, &identity)
		if err == nil {
			if canonical != v.Canonical || identity != v.SourceIdentity {
				return ErrConflict
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			if _, err = tx.ExecContext(ctx, "INSERT INTO candidates VALUES(?,?,?,?,?)", c.RunID, v.ID, v.Canonical, v.SourceIdentity, v.PayloadSHA); err != nil {
				return err
			}
		} else {
			return err
		}
		o := in.Occurrences[i]
		if _, err = tx.ExecContext(ctx, "INSERT INTO candidate_occurrences VALUES(?,?,?,?,?)", c.RunID, c.TaskID, v.ID, e.UnitID, o.PayloadSHA); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO coverage_events VALUES(?,?,?,?,?,?)", c.RunID, c.TaskID, e.UnitID, e.Status, e.Reason, e.PayloadSHA); err != nil {
		return err
	}
	if err = s.finishTx(ctx, tx, c, "completed", resultSHA, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func readHunt(ctx context.Context, tx *sql.Tx, snap *Snapshot) error {
	rows, err := tx.QueryContext(ctx, "SELECT id,canonical,source_identity,payload_sha FROM candidates WHERE run_id=? ORDER BY id", snap.Run.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v Candidate
		if err := rows.Scan(&v.ID, &v.Canonical, &v.SourceIdentity, &v.PayloadSHA); err != nil {
			rows.Close()
			return err
		}
		snap.Candidates = append(snap.Candidates, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT candidate_id,unit_id,task_id,payload_sha FROM candidate_occurrences WHERE run_id=? ORDER BY task_id,candidate_id", snap.Run.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v CandidateOccurrence
		if err := rows.Scan(&v.CandidateID, &v.UnitID, &v.TaskID, &v.PayloadSHA); err != nil {
			rows.Close()
			return err
		}
		snap.Occurrences = append(snap.Occurrences, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT unit_id,task_id,status,reason,payload_sha FROM coverage_events WHERE run_id=? ORDER BY task_id", snap.Run.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v CoverageEvent
		if err := rows.Scan(&v.UnitID, &v.TaskID, &v.Status, &v.Reason, &v.PayloadSHA); err != nil {
			rows.Close()
			return err
		}
		snap.CoverageHistory = append(snap.CoverageHistory, v)
	}
	err = rows.Err()
	rows.Close()
	return err
}
