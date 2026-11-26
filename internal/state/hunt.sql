CREATE TABLE hunt_batches (
 run_id TEXT NOT NULL, task_id TEXT NOT NULL, result_sha TEXT NOT NULL REFERENCES artifacts(sha), seed_sha TEXT NOT NULL,
 PRIMARY KEY(run_id,task_id), FOREIGN KEY(run_id,task_id) REFERENCES tasks(run_id,id)
);
CREATE TABLE candidates (
 run_id TEXT NOT NULL REFERENCES runs(id), id TEXT NOT NULL, canonical TEXT NOT NULL,
 source_identity TEXT NOT NULL, payload_sha TEXT NOT NULL REFERENCES artifacts(sha),
 PRIMARY KEY(run_id,id), UNIQUE(run_id,canonical)
);
CREATE TABLE candidate_occurrences (
 run_id TEXT NOT NULL, task_id TEXT NOT NULL, candidate_id TEXT NOT NULL, unit_id TEXT NOT NULL,
 payload_sha TEXT NOT NULL REFERENCES artifacts(sha),
 PRIMARY KEY(run_id,task_id,candidate_id),
 FOREIGN KEY(run_id,task_id) REFERENCES hunt_batches(run_id,task_id),
 FOREIGN KEY(run_id,candidate_id) REFERENCES candidates(run_id,id),
 FOREIGN KEY(run_id,unit_id) REFERENCES coverage_units(run_id,id)
);
CREATE TABLE coverage_events (
 run_id TEXT NOT NULL, task_id TEXT NOT NULL, unit_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('checked','candidate','blocked','deferred')),
 reason TEXT NOT NULL, payload_sha TEXT NOT NULL REFERENCES artifacts(sha),
 PRIMARY KEY(run_id,task_id),
 FOREIGN KEY(run_id,task_id) REFERENCES hunt_batches(run_id,task_id),
 FOREIGN KEY(run_id,unit_id) REFERENCES coverage_units(run_id,id)
);
CREATE TRIGGER hunt_batches_no_update BEFORE UPDATE ON hunt_batches BEGIN SELECT RAISE(ABORT,'hunt history is immutable'); END;
CREATE TRIGGER hunt_batches_no_delete BEFORE DELETE ON hunt_batches BEGIN SELECT RAISE(ABORT,'hunt history is immutable'); END;
CREATE TRIGGER candidates_no_update BEFORE UPDATE ON candidates BEGIN SELECT RAISE(ABORT,'candidate evidence is immutable'); END;
CREATE TRIGGER candidates_no_delete BEFORE DELETE ON candidates BEGIN SELECT RAISE(ABORT,'candidate evidence is immutable'); END;
CREATE TRIGGER occurrences_no_update BEFORE UPDATE ON candidate_occurrences BEGIN SELECT RAISE(ABORT,'candidate paths are immutable'); END;
CREATE TRIGGER occurrences_no_delete BEFORE DELETE ON candidate_occurrences BEGIN SELECT RAISE(ABORT,'candidate paths are immutable'); END;
CREATE TRIGGER coverage_events_no_update BEFORE UPDATE ON coverage_events BEGIN SELECT RAISE(ABORT,'coverage history is immutable'); END;
CREATE TRIGGER coverage_events_no_delete BEFORE DELETE ON coverage_events BEGIN SELECT RAISE(ABORT,'coverage history is immutable'); END;
PRAGMA user_version=5;
