CREATE TABLE coverage_batches (
 run_id TEXT NOT NULL,
 task_id TEXT NOT NULL,
 token TEXT NOT NULL REFERENCES attempts(token),
 result_sha TEXT NOT NULL REFERENCES artifacts(sha),
 seed_sha TEXT NOT NULL,
 PRIMARY KEY(run_id,task_id),
 FOREIGN KEY(run_id,task_id) REFERENCES tasks(run_id,id)
);
CREATE TABLE coverage_units (
 run_id TEXT NOT NULL REFERENCES runs(id),
 id TEXT NOT NULL,
 canonical TEXT NOT NULL,
 source_identity TEXT NOT NULL,
 payload_sha TEXT NOT NULL REFERENCES artifacts(sha),
 status TEXT NOT NULL CHECK(status IN ('planned','blocked','deferred','out_of_scope')),
 reason TEXT NOT NULL,
 task_id TEXT NOT NULL,
 PRIMARY KEY(run_id,id),
 UNIQUE(run_id,canonical),
 FOREIGN KEY(run_id,task_id) REFERENCES coverage_batches(run_id,task_id)
);
CREATE TRIGGER coverage_batches_no_update BEFORE UPDATE ON coverage_batches BEGIN SELECT RAISE(ABORT,'coverage projection history is immutable'); END;
CREATE TRIGGER coverage_batches_no_delete BEFORE DELETE ON coverage_batches BEGIN SELECT RAISE(ABORT,'coverage projection history is immutable'); END;
CREATE TRIGGER coverage_no_update BEFORE UPDATE ON coverage_units BEGIN SELECT RAISE(ABORT,'initial coverage evidence is immutable'); END;
CREATE TRIGGER coverage_no_delete BEFORE DELETE ON coverage_units BEGIN SELECT RAISE(ABORT,'initial coverage evidence is immutable'); END;
PRAGMA user_version=4;
