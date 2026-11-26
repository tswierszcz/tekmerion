CREATE TABLE decisions (
 run_id TEXT NOT NULL, task_id TEXT NOT NULL, candidate_id TEXT NOT NULL,
 label TEXT NOT NULL CHECK(label IN ('confirmed','needs_validation','rejected')),
 verifier TEXT NOT NULL CHECK(verifier IN ('supported','refuted','unresolved')),
 rules TEXT NOT NULL, reason TEXT NOT NULL, payload_sha TEXT NOT NULL REFERENCES artifacts(sha),
 PRIMARY KEY(run_id,task_id),
 FOREIGN KEY(run_id,task_id) REFERENCES tasks(run_id,id)
);
CREATE TRIGGER decisions_no_update BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT,'decision history is immutable'); END;
CREATE TRIGGER decisions_no_delete BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT,'decision history is immutable'); END;
PRAGMA user_version=7;
