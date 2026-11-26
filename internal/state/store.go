// Package state stores local research work transactionally in SQLite and
// evidence in an external, hash-addressed artifact directory. Paid admission
// atomically reserves a bounded request; live providers are integrated separately.
package state

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schema string

//go:embed budget.sql
var budgetSchema string

//go:embed dispatch.sql
var dispatchSchema string

//go:embed coverage.sql
var coverageSchema string

//go:embed hunt.sql
var huntSchema string

var (
	ErrBusy     = errors.New("task has an active lease")
	ErrLease    = errors.New("task lease is stale or expired")
	ErrTerminal = errors.New("task or run is terminal")
	ErrConflict = errors.New("conflicting result delivery")
)

const SchemaVersion = "tekmerion-state-5"

type Store struct {
	db  *sql.DB
	dir string
	now func() time.Time
}

// Create makes a new private state directory; an existing directory is refused.
func Create(ctx context.Context, dir string) (*Store, error) {
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(dir, "artifacts"), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "state.sqlite"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return open(ctx, dir, true)
}

// Open requires an existing database and never silently initializes one.
func Open(ctx context.Context, dir string) (*Store, error) { return open(ctx, dir, false) }

func open(ctx context.Context, dir string, initialize bool) (*Store, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(absolute, "state.sqlite")}
	q := url.Values{"mode": {"rw"}, "_foreign_keys": {"on"}, "_journal_mode": {"WAL"}, "_synchronous": {"FULL"}, "_busy_timeout": {"5000"}, "_txlock": {"immediate"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	if err := db.PingContext(ctx); err != nil {
		return fail(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if initialize && version == 0 {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return fail(err)
		}
		version = 1
	}
	if version == 1 {
		if _, err := tx.ExecContext(ctx, budgetSchema); err != nil {
			return fail(err)
		}
		version = 2
	}
	if version == 2 {
		if _, err := tx.ExecContext(ctx, dispatchSchema); err != nil {
			return fail(err)
		}
		version = 3
	}
	if version == 3 {
		if _, err := tx.ExecContext(ctx, coverageSchema); err != nil {
			return fail(err)
		}
		version = 4
	}
	if version == 4 {
		if _, err := tx.ExecContext(ctx, huntSchema); err != nil {
			return fail(err)
		}
		version = 5
	}
	if version != 5 {
		return fail(fmt.Errorf("state schema %d unsupported (want 5)", version))
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	return &Store{db: db, dir: absolute, now: time.Now}, nil
}
func (s *Store) Close() error { return s.db.Close() }

type Run struct {
	ID          string `json:"id"`
	ManifestSHA string `json:"manifest_sha256"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at_unix_nano"`
}
type Task struct {
	RunID      string `json:"run_id"`
	ID         string `json:"id"`
	Stage      string `json:"stage"`
	Paid       bool   `json:"paid"`
	InputSHA   string `json:"input_sha256"`
	Status     string `json:"status"`
	LeaseUntil *int64 `json:"lease_until_unix_nano,omitempty"`
}
type TaskInput struct {
	ID, Stage, InputSHA string
	Paid                bool
}

// Start commits the complete initial queue with its run identity atomically.
func (s *Store) Start(ctx context.Context, manifestSHA string, inputs []TaskInput) (*Run, error) {
	return s.start(ctx, manifestSHA, inputs, nil)
}

// StartBudget commits the immutable budget with the initial queue.
func (s *Store) StartBudget(ctx context.Context, manifestSHA string, inputs []TaskInput, config BudgetConfig) (*Run, error) {
	return s.start(ctx, manifestSHA, inputs, &config)
}
func (s *Store) start(ctx context.Context, manifestSHA string, inputs []TaskInput, config *BudgetConfig) (*Run, error) {
	if config != nil {
		if err := config.Validate(); err != nil {
			return nil, err
		}
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("run needs at least one task")
	}
	r := &Run{ID: "run-" + rand.Text(), ManifestSHA: manifestSHA, Status: "running", CreatedAt: s.now().UnixNano()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var existing int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM runs").Scan(&existing); err != nil {
		return nil, err
	}
	if existing != 0 {
		return nil, fmt.Errorf("state directory already contains a run")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO runs VALUES(?,?,?,?)", r.ID, r.ManifestSHA, r.Status, r.CreatedAt); err != nil {
		return nil, err
	}
	if config != nil {
		deadline, err := add64(r.CreatedAt, config.WallTimeSeconds*int64(time.Second))
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO budgets VALUES(?,?,?,?,?,?,?)", r.ID, config.Limit, config.ValidationReserve, config.ReportingReserve, config.MaxRequests, config.MaxTokens, deadline); err != nil {
			return nil, err
		}
	}
	for _, in := range inputs {
		if in.Paid && (config == nil || !paidStage(in.Stage)) {
			return nil, fmt.Errorf("paid task needs a configured budget and a research stage")
		}
		if in.ID == "" || in.Stage == "" {
			return nil, fmt.Errorf("task id and stage required")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(run_id,id,stage,input_sha,status,paid) VALUES(?,?,?,?,'pending',?)", r.ID, in.ID, in.Stage, in.InputSHA, in.Paid); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

type Claim struct {
	RunID, TaskID, Token string
	Number               int
	LeaseUntil           int64
}

// Claim exclusively acquires a task. Expiry appends an interrupted result for
// the old attempt before creating its successor in the same transaction.
func (s *Store) Claim(ctx context.Context, runID, taskID, worker string, ttl time.Duration) (*Claim, error) {

	if worker == "" || ttl <= 0 {
		return nil, fmt.Errorf("worker and positive lease duration required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := s.claimTx(ctx, tx, runID, taskID, worker, ttl, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return c, nil
}
func (s *Store) claimTx(ctx context.Context, tx *sql.Tx, runID, taskID, worker string, ttl time.Duration, paidRequest bool) (*Claim, error) {
	now := s.now()
	until := now.Add(ttl).UnixNano()
	if until <= now.UnixNano() {
		return nil, fmt.Errorf("lease duration overflows the clock")
	}
	var status, runStatus string
	var paid bool
	var token sql.NullString
	var expires sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT t.status,t.lease_token,t.lease_until,r.status,t.paid FROM tasks t JOIN runs r ON r.id=t.run_id WHERE t.run_id=? AND t.id=?`, runID, taskID).Scan(&status, &token, &expires, &runStatus, &paid)
	if err != nil {
		return nil, err
	}
	if paid != paidRequest {
		return nil, fmt.Errorf("paid tasks require atomic request admission; local tasks use Claim")
	}
	if runStatus != "running" || status == "completed" || status == "failed" {
		return nil, ErrTerminal
	}
	if status == "running" {
		if expires.Int64 > now.UnixNano() {
			return nil, ErrBusy
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_results VALUES(?,'interrupted',NULL,'lease expired before result delivery',?)", token.String, now.UnixNano()); err != nil {
			return nil, err
		}
	}
	c := &Claim{RunID: runID, TaskID: taskID, Token: rand.Text(), LeaseUntil: until}
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(number),0)+1 FROM attempts WHERE run_id=? AND task_id=?", runID, taskID).Scan(&c.Number); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO attempts VALUES(?,?,?,?,?,?)", c.Token, runID, taskID, c.Number, worker, now.UnixNano()); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET status='running',lease_token=?,lease_until=? WHERE run_id=? AND id=?", c.Token, until, runID, taskID); err != nil {
		return nil, err
	}
	return c, nil
}

// Renew retains the attempt identity; an expired claim cannot resurrect itself.
func (s *Store) Renew(ctx context.Context, c Claim, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("positive lease duration required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Read the clock after acquiring the write lock: time spent waiting for
	// another writer must never let an already expired owner renew itself.
	now := s.now()
	until := now.Add(ttl).UnixNano()
	if until <= now.UnixNano() {
		return fmt.Errorf("lease duration overflows the clock")
	}
	result, err := tx.ExecContext(ctx, `UPDATE tasks SET lease_until=? WHERE run_id=? AND id=? AND status='running' AND lease_token=? AND lease_until>? AND EXISTS(SELECT 1 FROM runs WHERE id=? AND status='running')`, until, c.RunID, c.TaskID, c.Token, now.UnixNano(), c.RunID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLease
	}
	return tx.Commit()
}

// Finish commits a terminal result and the task projection together. Identical
// redelivery is a no-op; contradictory or stale delivery is rejected.
func (s *Store) Finish(ctx context.Context, c Claim, outcome, resultSHA, diagnostic string) error {
	if outcome != "completed" && outcome != "failed" && outcome != "interrupted" {
		return fmt.Errorf("invalid attempt outcome %q", outcome)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.finishTx(ctx, tx, c, outcome, resultSHA, diagnostic); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) finishTx(ctx context.Context, tx *sql.Tx, c Claim, outcome, resultSHA, diagnostic string) error {
	var previous, previousSHA, previousDiagnostic string
	err := tx.QueryRowContext(ctx, `SELECT r.outcome,COALESCE(r.result_sha,''),r.diagnostic FROM attempt_results r JOIN attempts a ON a.token=r.token WHERE a.token=? AND a.run_id=? AND a.task_id=?`, c.Token, c.RunID, c.TaskID).Scan(&previous, &previousSHA, &previousDiagnostic)
	if err == nil {
		if previous == outcome && previousSHA == resultSHA && previousDiagnostic == diagnostic {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := s.now().UnixNano()
	var status string
	var token sql.NullString
	var until sql.NullInt64
	var runStatus string
	if err := tx.QueryRowContext(ctx, `SELECT t.status,t.lease_token,t.lease_until,r.status FROM tasks t JOIN runs r ON r.id=t.run_id WHERE t.run_id=? AND t.id=?`, c.RunID, c.TaskID).Scan(&status, &token, &until, &runStatus); err != nil {
		return err
	}
	if runStatus != "running" || status != "running" || token.String != c.Token || !token.Valid || until.Int64 <= now {
		return ErrLease
	}
	var result any
	if resultSHA != "" {
		result = resultSHA
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO attempt_results VALUES(?,?,?,?,?)", c.Token, outcome, result, diagnostic, now); err != nil {
		return err
	}
	next := outcome
	if outcome == "interrupted" {
		next = "pending"
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET status=?,lease_token=NULL,lease_until=NULL WHERE run_id=? AND id=?", next, c.RunID, c.TaskID); err != nil {
		return err
	}
	// A failed task stays terminal; remaining queued tasks can still run.
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET status=CASE WHEN EXISTS(SELECT 1 FROM tasks WHERE run_id=? AND status='failed') THEN 'failed' ELSE 'completed' END WHERE id=? AND NOT EXISTS(SELECT 1 FROM tasks WHERE run_id=? AND status IN ('pending','running'))`, c.RunID, c.RunID, c.RunID); err != nil {
		return err
	}
	return nil
}
