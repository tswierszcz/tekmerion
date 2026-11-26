ALTER TABLE tasks ADD COLUMN paid INTEGER NOT NULL DEFAULT 0 CHECK(paid IN (0,1));
CREATE TRIGGER task_paid_no_update BEFORE UPDATE OF paid ON tasks BEGIN SELECT RAISE(ABORT,'task execution kind is immutable'); END;
CREATE TABLE budgets (
 run_id TEXT PRIMARY KEY REFERENCES runs(id),
 limit_usd INTEGER NOT NULL CHECK(limit_usd>=0),
 validation_usd INTEGER NOT NULL CHECK(validation_usd>=0),
 reporting_usd INTEGER NOT NULL CHECK(reporting_usd>=0),
 max_requests INTEGER NOT NULL CHECK(max_requests>=0),
 max_tokens INTEGER NOT NULL CHECK(max_tokens>=0),
 deadline INTEGER NOT NULL
);
CREATE TABLE reservations (
 run_id TEXT NOT NULL REFERENCES budgets(run_id),
 request_id TEXT NOT NULL,
 token TEXT NOT NULL REFERENCES attempts(token),
 stage TEXT NOT NULL CHECK(stage IN ('recon','hunt','validate','report')),
 model TEXT NOT NULL,
 provider TEXT NOT NULL,
 pricing_sha TEXT NOT NULL REFERENCES artifacts(sha),
 request_sha TEXT NOT NULL REFERENCES artifacts(sha),
 max_usd INTEGER NOT NULL CHECK(max_usd>=0),
 max_tokens INTEGER NOT NULL CHECK(max_tokens>0),
 protected_credit INTEGER NOT NULL CHECK(protected_credit>=0 AND protected_credit<=max_usd),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(run_id,request_id)
);
CREATE TABLE charges (
 run_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 response_id TEXT NOT NULL,
 cost_usd INTEGER NOT NULL CHECK(cost_usd>=0),
 actual_tokens INTEGER CHECK(actual_tokens>=0),
 evidence_sha TEXT NOT NULL REFERENCES artifacts(sha),
 recorded_at INTEGER NOT NULL,
 PRIMARY KEY(run_id,request_id),
 UNIQUE(run_id,response_id),
 FOREIGN KEY(run_id,request_id) REFERENCES reservations(run_id,request_id)
);
CREATE TABLE uncertain_charges (
 run_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 observation_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 evidence_sha TEXT NOT NULL REFERENCES artifacts(sha),
 recorded_at INTEGER NOT NULL,
 PRIMARY KEY(run_id,observation_id),
 FOREIGN KEY(run_id,request_id) REFERENCES reservations(run_id,request_id)
);
CREATE TABLE budget_halts (
 run_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 PRIMARY KEY(run_id,request_id),
 FOREIGN KEY(run_id,request_id) REFERENCES reservations(run_id,request_id)
);
CREATE TRIGGER budgets_no_update BEFORE UPDATE ON budgets BEGIN SELECT RAISE(ABORT,'budget configuration is immutable'); END;
CREATE TRIGGER budgets_no_delete BEFORE DELETE ON budgets BEGIN SELECT RAISE(ABORT,'budget configuration is immutable'); END;
CREATE TRIGGER reservations_no_update BEFORE UPDATE ON reservations BEGIN SELECT RAISE(ABORT,'request reservations are immutable'); END;
CREATE TRIGGER reservations_no_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'request reservations are immutable'); END;
CREATE TRIGGER charges_no_update BEFORE UPDATE ON charges BEGIN SELECT RAISE(ABORT,'reported charges are immutable'); END;
CREATE TRIGGER charges_no_delete BEFORE DELETE ON charges BEGIN SELECT RAISE(ABORT,'reported charges are immutable'); END;
CREATE TRIGGER uncertain_no_update BEFORE UPDATE ON uncertain_charges BEGIN SELECT RAISE(ABORT,'charge observations are immutable'); END;
CREATE TRIGGER uncertain_no_delete BEFORE DELETE ON uncertain_charges BEGIN SELECT RAISE(ABORT,'charge observations are immutable'); END;
CREATE TRIGGER halts_no_update BEFORE UPDATE ON budget_halts BEGIN SELECT RAISE(ABORT,'budget discrepancies are immutable'); END;
CREATE TRIGGER halts_no_delete BEFORE DELETE ON budget_halts BEGIN SELECT RAISE(ABORT,'budget discrepancies are immutable'); END;
PRAGMA user_version=2;
