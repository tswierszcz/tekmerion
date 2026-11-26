package state

import (
	"context"
	"database/sql"
	"fmt"
)

type Attempt struct {
	Token      string `json:"token"`
	RunID      string `json:"run_id"`
	TaskID     string `json:"task_id"`
	Number     int    `json:"number"`
	Worker     string `json:"worker"`
	StartedAt  int64  `json:"started_at_unix_nano"`
	Outcome    string `json:"outcome"`
	ResultSHA  string `json:"result_sha256,omitempty"`
	Diagnostic string `json:"diagnostic,omitempty"`
	FinishedAt *int64 `json:"finished_at_unix_nano,omitempty"`
}
type Snapshot struct {
	Candidates      []Candidate           `json:"candidates"`
	Occurrences     []CandidateOccurrence `json:"candidate_occurrences"`
	CoverageHistory []CoverageEvent       `json:"coverage_history"`
	Schema          string                `json:"schema_version"`
	Run             Run                   `json:"run"`
	Tasks           []Task                `json:"tasks"`
	Attempts        []Attempt             `json:"attempts"`
	Artifacts       []Artifact            `json:"artifacts"`
	Coverage        []CoverageUnit        `json:"coverage"`
	Forecasts       []Forecast            `json:"forecasts"`
	Budget          *BudgetSnapshot       `json:"budget,omitempty"`
}

// Snapshot reads one transactionally consistent projection in stable order.
// It does not mutate task leases, execute work or contact providers.
func (s *Store) Snapshot(ctx context.Context) (*Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snap := &Snapshot{Schema: SchemaVersion, Tasks: []Task{}, Attempts: []Attempt{}, Artifacts: []Artifact{}, Forecasts: []Forecast{}, Coverage: []CoverageUnit{}}
	if err := tx.QueryRowContext(ctx, "SELECT id,manifest_sha,status,created_at FROM runs").Scan(&snap.Run.ID, &snap.Run.ManifestSHA, &snap.Run.Status, &snap.Run.CreatedAt); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT run_id,id,stage,input_sha,status,lease_until,paid FROM tasks ORDER BY id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t Task
		var until sql.NullInt64
		if err := rows.Scan(&t.RunID, &t.ID, &t.Stage, &t.InputSHA, &t.Status, &until, &t.Paid); err != nil {
			rows.Close()
			return nil, err
		}
		if until.Valid {
			v := until.Int64
			t.LeaseUntil = &v
		}
		snap.Tasks = append(snap.Tasks, t)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT a.token,a.run_id,a.task_id,a.number,a.worker,a.started_at,COALESCE(r.outcome,'running'),COALESCE(r.result_sha,''),COALESCE(r.diagnostic,''),r.finished_at FROM attempts a LEFT JOIN attempt_results r ON a.token=r.token ORDER BY a.task_id,a.number`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a Attempt
		var finished sql.NullInt64
		if err := rows.Scan(&a.Token, &a.RunID, &a.TaskID, &a.Number, &a.Worker, &a.StartedAt, &a.Outcome, &a.ResultSHA, &a.Diagnostic, &finished); err != nil {
			rows.Close()
			return nil, err
		}
		if finished.Valid {
			v := finished.Int64
			a.FinishedAt = &v
		}
		snap.Attempts = append(snap.Attempts, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT sha,size,media_type FROM artifacts ORDER BY sha")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(&a.SHA, &a.Size, &a.MediaType); err != nil {
			rows.Close()
			return nil, err
		}
		snap.Artifacts = append(snap.Artifacts, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT report_sha,plan_sha,pricing_sha,recorded_at FROM forecasts WHERE run_id=? ORDER BY recorded_at,report_sha", snap.Run.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f Forecast
		if err := rows.Scan(&f.ReportSHA, &f.PlanSHA, &f.PricingSHA, &f.RecordedAt); err != nil {
			rows.Close()
			return nil, err
		}
		snap.Forecasts = append(snap.Forecasts, f)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT id,canonical,source_identity,payload_sha,status,reason,task_id FROM coverage_units WHERE run_id=? ORDER BY id", snap.Run.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		unit := CoverageUnit{RunID: snap.Run.ID}
		if err := rows.Scan(&unit.ID, &unit.Canonical, &unit.SourceIdentity, &unit.PayloadSHA, &unit.Status, &unit.Reason, &unit.TaskID); err != nil {
			rows.Close()
			return nil, err
		}
		snap.Coverage = append(snap.Coverage, unit)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := readHunt(ctx, tx, snap); err != nil {
		return nil, err
	}
	snap.Budget, err = readBudget(ctx, tx, snap.Run.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snap, nil
}

// Verify checks saved evidence before a report claims a complete local export.
func (s *Store) Verify(ctx context.Context, snapshot *Snapshot) error {
	for _, a := range snapshot.Artifacts {
		if _, err := s.Get(ctx, a.SHA); err != nil {
			return fmt.Errorf("saved evidence: %w", err)
		}
	}
	return nil
}
