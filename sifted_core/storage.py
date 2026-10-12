"""SQLite persistence with explicit migrations and transactional job transitions.

JSON documents retain the public case/run response format. Relationships, queue
ownership, events and file manifests are stored independently of those documents.
"""
import json
import hashlib
import uuid
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .integrity import canonical


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class StoreError(ValueError):
    pass


class Repository:
    SCHEMA_VERSION = 2

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
            if version < 2:
                for statement in INTAKE_SCHEMA:
                    db.execute(statement)
                db.execute("PRAGMA user_version=2")

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
                if run.get("case_id") and not input_record.get("source_run_id"):
                    case_row = db.execute("SELECT data FROM cases WHERE id=?", (run["case_id"],)).fetchone()
                    if not case_row:
                        raise StoreError("Case not found.")
                    case = json.loads(case_row[0])
                    item = next((x for x in case.get("artifacts", []) if x.get("path") == run["source_path"]), None)
                    if item and item.get("status") == "retired":
                        raise StoreError("Evidence is retired. Its custody record is retained.")
                    if item and item.get("status") == "pending":
                        raise StoreError("Evidence intake is already queued or running.")
                    metadata = input_record.pop("registration", {})
                    if not item:
                        item = {"id": uuid.uuid4().hex, "path": run["source_path"], "hash": "",
                                "label": metadata.get("label") or Path(run["source_path"]).name,
                                "type": metadata.get("type") or "other", "type_basis": "analyst" if metadata.get("type") else "content",
                                "added_at": utc_now(), "status": "pending", "intake": metadata}
                        case.setdefault("artifacts", []).append(item)
                        self._custody(db, case["id"], item["id"], "intake_requested", {**metadata, "path": item["path"], "run_id": run["id"]})
                    elif metadata and run["tool"] != "evidence-intake":
                        raise StoreError("Evidence is already registered.")
                    input_record["artifact_id"] = item["id"]
                    input_record["baseline_sha256"] = item.get("hash") or item.get("intake", {}).get("expected_sha256") or metadata.get("expected_sha256") or input_record.get("baseline_sha256")
                    input_record["baseline_manifest"] = item.get("manifest")
                    input_record["custodian"] = metadata.get("custodian") or item.get("intake", {}).get("custodian") or "Unattributed"
                    if run["tool"] == "evidence-intake" or item.get("status") != "ready":
                        item.update(status="pending", intake_run_id=run["id"])
                    self._custody(db, case["id"], item["id"], "verification_queued" if run["tool"] == "evidence-intake" else "analysis_queued",
                                  {"run_id": run["id"], "tool": run["tool"], "custodian": input_record["custodian"]})
                    db.execute("UPDATE cases SET data=? WHERE id=?", (json.dumps(case), case["id"]))
                elif run.get("case_id") and input_record.get("source_run_id"):
                    parent = db.execute("SELECT data FROM run_inputs WHERE run_id=? AND role='primary'", (input_record["source_run_id"],)).fetchone()
                    source = json.loads(parent[0]) if parent else {}
                    root_id = source.get("custody_evidence_id") or (source.get("artifact_id") if not source.get("source_run_id") else None)
                    if root_id:
                        input_record["custody_evidence_id"] = root_id
                        self._custody(db, run["case_id"], root_id, "analysis_queued", {
                            "run_id": run["id"], "tool": run["tool"], "source_run_id": input_record["source_run_id"],
                            "path": input_record["path"], "baseline_sha256": input_record["baseline_sha256"]})
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
                self._finish_evidence(db, run, [])
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
        files = list(files)
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
            self._finish_evidence(db, run, files)
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

    @staticmethod
    def _custody(db, case_id, evidence_id, kind, details):
        previous = db.execute("SELECT digest FROM evidence_events WHERE case_id=? AND evidence_id=? ORDER BY sequence DESC LIMIT 1",
                              (case_id, evidence_id)).fetchone()
        event = {"case_id": case_id, "evidence_id": evidence_id, "event": kind, "recorded_at": utc_now(),
                 "details": details, "previous": previous[0] if previous else None}
        digest = hashlib.sha256(canonical(event)).hexdigest()
        db.execute("INSERT INTO evidence_events(case_id,evidence_id,data,digest) VALUES (?,?,?,?)",
                   (case_id, evidence_id, json.dumps(event), digest))

    def custody(self, case_id, evidence_id):
        with self.connection() as db:
            events = [{**json.loads(row["data"]), "digest": row["digest"]} for row in db.execute(
                "SELECT data,digest FROM evidence_events WHERE case_id=? AND evidence_id=? ORDER BY sequence", (case_id, evidence_id))]
        return {"format": "sifted-custody-v1", "events": events, "event_count": len(events),
                "head": events[-1]["digest"] if events else None}

    def accept_evidence(self, run_id, observed, digest, manifest):
        """Record verified bytes and their profile before a tool consumes them."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            run = json.loads(db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()[0])
            source = json.loads(db.execute("SELECT data FROM run_inputs WHERE run_id=? AND role='primary'", (run_id,)).fetchone()[0])
            if not run.get("case_id") or not source.get("artifact_id"):
                return
            if source.get("source_run_id"):
                if source.get("custody_evidence_id"):
                    self._custody(db, run["case_id"], source["custody_evidence_id"], "derived_input_verified", {
                        "run_id": run_id, "source_run_id": source["source_run_id"], "path": source["path"],
                        "sha256": digest, "profile": observed})
                return
            case = json.loads(db.execute("SELECT data FROM cases WHERE id=?", (run["case_id"],)).fetchone()[0])
            item = next(x for x in case["artifacts"] if x["id"] == source["artifact_id"])
            if item.get("status") == "retired":
                raise StoreError("Evidence was retired before verification.")
            if item.get("hash") and item["hash"] != digest:
                raise StoreError("Evidence hash differs from its original baseline.")
            if item.get("manifest") is not None and item["manifest"] != manifest:
                raise StoreError("Evidence manifest differs from its original baseline.")
            from .evidence_profile import evidence_type
            if item.get("type_basis") != "analyst":
                item.update(type=evidence_type(observed), type_basis="content")
            item.update(hash=digest, manifest=manifest, profile=observed, status="ready", verified_at=utc_now(), error=None)
            self._custody(db, case["id"], item["id"], "verification_succeeded", {
                "run_id": run_id, "sha256": digest, "hash_scope": "directory manifest" if source["kind"] == "directory" else "source file",
                "manifest": manifest, "profile": observed, "custodian": source.get("custodian", "Unattributed")})
            db.execute("UPDATE cases SET data=? WHERE id=?", (json.dumps(case), case["id"]))

    def _finish_evidence(self, db, run, files):
        source_row = db.execute("SELECT data FROM run_inputs WHERE run_id=? AND role='primary'", (run["id"],)).fetchone()
        source = json.loads(source_row[0]) if source_row else {}
        if not run.get("case_id") or not source.get("artifact_id"):
            return
        if source.get("source_run_id"):
            if source.get("custody_evidence_id"):
                self._custody(db, run["case_id"], source["custody_evidence_id"], "analysis_completed", {
                    "run_id": run["id"], "source_run_id": source["source_run_id"], "path": source["path"],
                    "status": run["status"], "error": run.get("error"), "input_sha256": run.get("input_sha256"), "outputs": list(files)})
            return
        case = json.loads(db.execute("SELECT data FROM cases WHERE id=?", (run["case_id"],)).fetchone()[0])
        item = next((x for x in case.get("artifacts", []) if x["id"] == source["artifact_id"]), None)
        if not item:
            return
        if (item.get("status") == "pending" and item.get("intake_run_id") == run["id"]) or run.get("integrity_status") == "failed":
            item.update(status="failed", error=run.get("error") or run["status"])
            db.execute("UPDATE cases SET data=? WHERE id=?", (json.dumps(case), case["id"]))
        self._custody(db, case["id"], item["id"], "intake_completed" if run["tool"] == "evidence-intake" else "analysis_completed", {
            "run_id": run["id"], "tool": run["tool"], "status": run["status"], "error": run.get("error"),
            "input_sha256": run.get("input_sha256"), "outputs": list(files)})

    def change_evidence(self, case_id, evidence_id, changes, event, details):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                raise StoreError("Case not found.")
            case = json.loads(row[0])
            item = next((x for x in case.get("artifacts", []) if x["id"] == evidence_id), None)
            if not item:
                raise StoreError("Evidence not found.")
            if item.get("status") == "retired":
                raise StoreError("Evidence is retired.")
            if changes.get("status") == "retired":
                for row in db.execute("SELECT data FROM runs WHERE case_id=? AND status IN ('queued','running')", (case_id,)):
                    if json.loads(row[0])["source_path"] == item["path"]:
                        raise StoreError("Wait for active evidence work to finish before retiring it.")
            self._custody(db, case_id, evidence_id, event, {"before": {key: item.get(key) for key in changes}, "after": changes, **details})
            item.update(changes)
            db.execute("UPDATE cases SET data=? WHERE id=?", (json.dumps(case), case_id))
            return item

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


INTAKE_SCHEMA = [
    """CREATE TABLE evidence_events(sequence INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
       evidence_id TEXT NOT NULL, data TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX evidence_history ON evidence_events(case_id,evidence_id,sequence)",
    "CREATE TRIGGER custody_no_update BEFORE UPDATE ON evidence_events BEGIN SELECT RAISE(ABORT, 'Custody events are append-only'); END",
    "CREATE TRIGGER custody_no_delete BEFORE DELETE ON evidence_events BEGIN SELECT RAISE(ABORT, 'Custody events are append-only'); END",
    "CREATE TABLE evidence_uploads(id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), data TEXT NOT NULL)",
]
