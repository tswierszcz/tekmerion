CREATE TABLE runs (
 id TEXT PRIMARY KEY,
 manifest_sha TEXT NOT NULL REFERENCES artifacts(sha),
 status TEXT NOT NULL CHECK(status IN ('running','completed','failed','cancelled')),
 created_at INTEGER NOT NULL
);
CREATE TABLE artifacts (
 sha TEXT PRIMARY KEY,
 size INTEGER NOT NULL CHECK(size >= 0),
 media_type TEXT NOT NULL
);
CREATE TABLE tasks (
 run_id TEXT NOT NULL REFERENCES runs(id),
 id TEXT NOT NULL,
 stage TEXT NOT NULL,
 input_sha TEXT NOT NULL REFERENCES artifacts(sha),
 status TEXT NOT NULL CHECK(status IN ('pending','running','completed','failed')),
 lease_token TEXT,
 lease_until INTEGER,
 PRIMARY KEY(run_id,id),
 CHECK((status='running') = (lease_token IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE TABLE attempts (
 token TEXT PRIMARY KEY,
 run_id TEXT NOT NULL,
 task_id TEXT NOT NULL,
 number INTEGER NOT NULL CHECK(number > 0),
 worker TEXT NOT NULL,
 started_at INTEGER NOT NULL,
 FOREIGN KEY(run_id,task_id) REFERENCES tasks(run_id,id),
 UNIQUE(run_id,task_id,number)
);
CREATE TABLE attempt_results (
 token TEXT PRIMARY KEY REFERENCES attempts(token),
 outcome TEXT NOT NULL CHECK(outcome IN ('completed','failed','interrupted')),
 result_sha TEXT REFERENCES artifacts(sha),
 diagnostic TEXT NOT NULL,
 finished_at INTEGER NOT NULL
);
CREATE TRIGGER attempts_no_update BEFORE UPDATE ON attempts BEGIN SELECT RAISE(ABORT,'attempt history is immutable'); END;
CREATE TRIGGER attempts_no_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,'attempt history is immutable'); END;
CREATE TRIGGER results_no_update BEFORE UPDATE ON attempt_results BEGIN SELECT RAISE(ABORT,'attempt results are immutable'); END;
CREATE TRIGGER results_no_delete BEFORE DELETE ON attempt_results BEGIN SELECT RAISE(ABORT,'attempt results are immutable'); END;
CREATE TRIGGER artifacts_no_update BEFORE UPDATE ON artifacts BEGIN SELECT RAISE(ABORT,'artifact metadata is immutable'); END;
CREATE TRIGGER artifacts_no_delete BEFORE DELETE ON artifacts BEGIN SELECT RAISE(ABORT,'artifact metadata is immutable'); END;
CREATE TRIGGER run_identity_no_update BEFORE UPDATE OF id,manifest_sha,created_at ON runs BEGIN SELECT RAISE(ABORT,'run identity is immutable'); END;
CREATE TRIGGER task_identity_no_update BEFORE UPDATE OF run_id,id,stage,input_sha ON tasks BEGIN SELECT RAISE(ABORT,'task identity is immutable'); END;
PRAGMA user_version=1;
