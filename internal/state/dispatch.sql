CREATE TABLE dispatches (
 run_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 dispatched_at INTEGER NOT NULL,
 PRIMARY KEY(run_id,request_id),
 FOREIGN KEY(run_id,request_id) REFERENCES reservations(run_id,request_id)
);
CREATE TRIGGER dispatches_no_update BEFORE UPDATE ON dispatches BEGIN SELECT RAISE(ABORT,'dispatch history is immutable'); END;
CREATE TRIGGER dispatches_no_delete BEFORE DELETE ON dispatches BEGIN SELECT RAISE(ABORT,'dispatch history is immutable'); END;
CREATE TABLE forecasts (
 run_id TEXT NOT NULL REFERENCES runs(id),
 report_sha TEXT NOT NULL REFERENCES artifacts(sha),
 plan_sha TEXT NOT NULL REFERENCES artifacts(sha),
 pricing_sha TEXT NOT NULL REFERENCES artifacts(sha),
 recorded_at INTEGER NOT NULL,
 PRIMARY KEY(run_id,report_sha)
);
CREATE TRIGGER forecasts_no_update BEFORE UPDATE ON forecasts BEGIN SELECT RAISE(ABORT,'forecast history is immutable'); END;
CREATE TRIGGER forecasts_no_delete BEFORE DELETE ON forecasts BEGIN SELECT RAISE(ABORT,'forecast history is immutable'); END;
PRAGMA user_version=3;
