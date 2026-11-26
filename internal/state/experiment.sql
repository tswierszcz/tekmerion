CREATE TABLE reproductions (
 run_id TEXT NOT NULL, task_id TEXT NOT NULL, candidate_id TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('reproduced','not_reproduced','inconclusive','blocked')),
 reason TEXT NOT NULL, payload_sha TEXT NOT NULL REFERENCES artifacts(sha),
 PRIMARY KEY(run_id,task_id),
 FOREIGN KEY(run_id,task_id) REFERENCES tasks(run_id,id)
);
CREATE TRIGGER reproductions_no_update BEFORE UPDATE ON reproductions BEGIN SELECT RAISE(ABORT,'reproduction history is immutable'); END;
CREATE TRIGGER reproductions_no_delete BEFORE DELETE ON reproductions BEGIN SELECT RAISE(ABORT,'reproduction history is immutable'); END;
PRAGMA user_version=6;
