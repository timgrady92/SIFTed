"""SQLite persistence with explicit migrations and transactional job transitions.

JSON documents retain the public case/run response format. Relationships, queue
ownership, events and file manifests are stored independently of those documents.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class StoreError(ValueError):
    pass


class Repository:
    SCHEMA_VERSION = 1

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > self.SCHEMA_VERSION:
                raise StoreError("Database schema is newer than this application.")
            if version == 0:
                for statement in SCHEMA:
                    db.execute(statement)
                db.execute("PRAGMA user_version=1")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def cases(self):
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT data FROM cases ORDER BY rowid")]

    def case(self, case_id):
        with self.connection() as db:
            row = db.execute("SELECT data FROM cases WHERE id=?", (case_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def add_case(self, case):
        with self.connection() as db:
            db.execute("INSERT INTO cases VALUES (?,?)", (case["id"], json.dumps(case)))

    def mutate_case(self, case_id, mutation):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                raise StoreError("Case not found.")
            case = json.loads(row[0])
            mutation(case)
            db.execute("UPDATE cases SET data=? WHERE id=?", (json.dumps(case), case_id))
            return case

    def runs(self, statuses=None, case_id=None):
        conditions, parameters = [], []
        if statuses:
            conditions.append("status IN (" + ",".join("?" for _ in statuses) + ")")
            parameters.extend(statuses)
        if case_id is not None:
            conditions.append("case_id=?")
            parameters.append(case_id)
        query = "SELECT data FROM runs" + (" WHERE " + " AND ".join(conditions) if conditions else "")
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute(query + " ORDER BY created_at,id", parameters)]

    def run(self, run_id):
        with self.connection() as db:
            row = db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def enqueue(self, run, input_record):
        try:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO runs(id,case_id,status,output_path,created_at,data) VALUES (?,?,?,?,?,?)",
                           (run["id"], run.get("case_id"), "queued", run["output_path"],
                            run["created_at"], json.dumps(run)))
                db.execute("INSERT INTO run_inputs VALUES (?,?,?)",
                           (run["id"], "primary", json.dumps(input_record)))
                self._event(db, run["id"], "status", "Queued for execution.")
        except sqlite3.IntegrityError as exc:
            raise StoreError("Case is missing or output folder is already reserved by a run.") from exc

    @staticmethod
    def _event(db, run_id, event_type, message):
        db.execute("INSERT INTO events(run_id,type,message,created_at) VALUES (?,?,?,?)",
                   (run_id, event_type, str(message), utc_now()))

    def emit(self, run_id, event_type, message):
        with self.connection() as db:
            self._event(db, run_id, event_type, message)

    def events(self, run_id, after=0):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                "SELECT id,type,message FROM events WHERE run_id=? AND id>? ORDER BY id LIMIT 100",
                (run_id, after))]

    def input(self, run_id):
        with self.connection() as db:
            row = db.execute("SELECT data FROM run_inputs WHERE run_id=? AND role='primary'", (run_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def update(self, run_id, changes):
        if {"id", "case_id", "output_path", "created_at", "plan", "parameters", "status"} & changes.keys():
            raise StoreError("Job identity, plan and state cannot be changed through a progress update.")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise StoreError("Run not found.")
            run = json.loads(row[0])
            run.update(changes)
            db.execute("UPDATE runs SET data=?,status=? WHERE id=?", (json.dumps(run), run["status"], run_id))
            return run

    def claim(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM runs WHERE status='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            if not row:
                return None
            run = json.loads(row[0])
            run.update(status="running", started_at=utc_now())
            db.execute("UPDATE runs SET status='running',data=? WHERE id=?", (json.dumps(run), run["id"]))
            self._event(db, run["id"], "status", "Running...")
            return run

    def request_cancel(self, run_id):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise StoreError("Run not found.")
            run = json.loads(row[0])
            if run["status"] == "queued":
                run.update(status="cancelled", exit_code=130, completed_at=utc_now())
                self._event(db, run_id, "status", "Run cancelled before execution.")
                self._event(db, run_id, "done", 130)
            elif run["status"] == "running" and not run.get("finalizing") and not run.get("cancel_requested"):
                run["cancel_requested"] = True
                self._event(db, run_id, "status", "Cancellation requested...")
            db.execute("UPDATE runs SET status=?,data=? WHERE id=?", (run["status"], json.dumps(run), run_id))
            return run

    def begin_finalization(self, run_id):
        """Close cancellation atomically before publishing immutable results."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = json.loads(db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()[0])
            run["finalizing"] = True
            db.execute("UPDATE runs SET data=? WHERE id=?", (json.dumps(run), run_id))
            return run.get("cancel_requested", False)

    def finish(self, run_id, changes, files=()):
        """Publish the manifest, terminal state and completion event together."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = json.loads(db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()[0])
            if run["status"] != "running" or changes.get("status") not in {"success", "error", "cancelled", "interrupted"}:
                raise StoreError("Only a claimed job can transition to a terminal state.")
            run.update(changes, completed_at=utc_now())
            db.execute("DELETE FROM artifacts WHERE run_id=?", (run_id,))
            for entry in files:
                db.execute("INSERT INTO artifacts(run_id,path,data) VALUES (?,?,?)",
                           (run_id, entry["path"], json.dumps(entry)))
            db.execute("UPDATE runs SET status=?,data=? WHERE id=?", (run["status"], json.dumps(run), run_id))
            self._event(db, run_id, "status", run.get("error") or "Run completed.")
            self._event(db, run_id, "done", run["exit_code"])

    def artifacts(self, run_id):
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT data FROM artifacts WHERE run_id=? ORDER BY id", (run_id,))]

    def artifact_by_path(self, path):
        with self.connection() as db:
            row = db.execute("SELECT a.id,a.data,r.status FROM artifacts a JOIN runs r ON r.id=a.run_id WHERE a.path=?",
                             (path,)).fetchone()
            return {**json.loads(row["data"]), "id": row["id"], "status": row["status"]} if row else None

    def derived_inputs(self, case_id):
        with self.connection() as db:
            values = [dict(json.loads(row["data"]), id=row["id"]) for row in db.execute(
                "SELECT a.id,a.data FROM artifacts a JOIN runs r ON r.id=a.run_id WHERE r.case_id=? AND r.status='success' ORDER BY a.id",
                (case_id,))]
        return [entry for entry in values if entry.get("complete") and not entry["name"].startswith("_sifted/")]

    def heartbeat(self, pid):
        with self.connection() as db:
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('worker',?)",
                       (json.dumps({"pid": pid, "heartbeat_at": utc_now()}),))

    def worker_status(self):
        with self.connection() as db:
            row = db.execute("SELECT value FROM metadata WHERE key='worker'").fetchone()
        data = json.loads(row[0]) if row else {}
        fresh = bool(data) and (datetime.now(timezone.utc) - datetime.fromisoformat(data["heartbeat_at"])).total_seconds() < 15
        return {**data, "status": "online" if fresh else "offline"}

    def clear_heartbeat(self, pid):
        with self.connection() as db:
            row = db.execute("SELECT value FROM metadata WHERE key='worker'").fetchone()
            if row and json.loads(row[0])["pid"] == pid:
                db.execute("DELETE FROM metadata WHERE key='worker'")


SCHEMA = [
    "CREATE TABLE cases(id TEXT PRIMARY KEY, data TEXT NOT NULL)",
    """CREATE TABLE runs(id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases(id),
       status TEXT NOT NULL CHECK(status IN ('queued','running','success','error','cancelled','interrupted')),
       output_path TEXT, created_at TEXT NOT NULL, data TEXT NOT NULL)""",
    "CREATE INDEX queue_order ON runs(status,created_at,id)",
    "CREATE INDEX case_runs ON runs(case_id,created_at,id)",
    "CREATE UNIQUE INDEX reserved_output ON runs(output_path)",
    """CREATE TABLE run_inputs(run_id TEXT REFERENCES runs(id), role TEXT NOT NULL,
       data TEXT NOT NULL, PRIMARY KEY(run_id,role))""",
    """CREATE TABLE events(id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
       type TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL)""",
    "CREATE INDEX run_event_cursor ON events(run_id,id)",
    """CREATE TABLE artifacts(id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
       path TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(run_id,path))""",
    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
]
