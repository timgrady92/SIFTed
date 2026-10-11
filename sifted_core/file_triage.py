"""Indexed filesystem listings; every view and selected entry belongs to a verified run.

The index is a published, hashed tool output, built by the worker from fls.csv.
It contains names reported by TSK, never content classifications inferred from names.
"""
from contextlib import closing, contextmanager
import csv
import hashlib
import os
from pathlib import Path, PurePosixPath
import sqlite3

from .tool_base import ValidationError, allowed, signature


INDEX_NAME = "inventory.sqlite3"


def build_index(output, check):
    target = output / INDEX_NAME
    # The worker owns this fresh directory; never reuse an existing database.
    with target.open("xb"):
        pass
    with closing(sqlite3.connect(target)) as db:
        interruption = None

        def progress():
            nonlocal interruption
            try:
                check()
            except Exception as exc:
                interruption = exc
                return 1
            return 0

        db.set_progress_handler(progress, 10000)
        try:
            with db:
                db.execute("""CREATE TABLE entries(id INTEGER PRIMARY KEY, address TEXT NOT NULL,
                           path TEXT NOT NULL, parent TEXT, name TEXT NOT NULL, kind TEXT NOT NULL,
                           deleted INTEGER NOT NULL, reallocated INTEGER NOT NULL)""")
                with (output / "fls.csv").open(newline="", encoding="utf-8") as handle:
                    for ordinal, row in enumerate(csv.DictReader(handle), 1):
                        check()
                        path = row["Name"]
                        parts = path.split("/")
                        safe = bool(path) and not path.startswith("/") and all(p and p not in {".", ".."} for p in parts)
                        parent = "/".join(parts[:-1]) if safe else None
                        db.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)",
                                   (ordinal, row["Metadata Address"], path, parent, parts[-1], row["Kind"],
                                    row["Deleted"] == "Yes", row["Reallocated"] == "Yes"))
                db.execute("CREATE INDEX entry_parent ON entries(parent,kind,name,id)")
                db.execute("CREATE INDEX entry_state ON entries(deleted,kind,id)")
                check()
                db.execute("CREATE INDEX entry_path ON entries(path,kind,id)")
                check()
                db.execute("PRAGMA user_version=1")
        except sqlite3.Error:
            if interruption:
                raise interruption
            raise
    check()


@contextmanager
def verified_index(run, repository, settings):
    if not run or run["tool"] != "fls" or run["status"] != "success" or not run.get("analysis", {}).get("inventory"):
        raise ValidationError("Build a file inventory to open triage.")
    path = Path(run["output_path"]) / INDEX_NAME
    entry = next((item for item in repository.artifacts(run["id"])
                  if item["path"] == str(path) and item.get("complete")), None)
    if not entry or not allowed(str(path), settings.output_roots):
        raise ValidationError("File inventory is outside allowed roots or has no complete manifest.")
    try:
        before = signature(path)
        digest = hashlib.sha256()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        # Keep the verified file descriptor open while SQLite reads that inode.
        with os.fdopen(descriptor, "rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            if digest.hexdigest() != entry["sha256"] or signature(path) != before:
                raise ValidationError("File inventory changed; rebuild it before continuing triage.")
            uri = f"file:/proc/self/fd/{handle.fileno()}?mode=ro&immutable=1"
            db = sqlite3.connect(uri, uri=True)
            db.row_factory = sqlite3.Row
            try:
                if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                    raise ValidationError("Unsupported file inventory format; rebuild the inventory.")
                yield db
                if signature(path) != before:
                    raise ValidationError("File inventory changed while reading; rebuild it before continuing triage.")
            finally:
                db.close()
    except (OSError, sqlite3.Error) as exc:
        raise ValidationError("Unable to read the verified file inventory; rebuild it before continuing.") from exc


def entry_for(run, entry_id, repository, settings):
    with verified_index(run, repository, settings) as db:
        row = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
        if not row:
            raise ValidationError("Selected entry does not belong to this file inventory.")
        return dict(row)


def validate_entry(plan, context, repository, settings):
    entry_id = plan.parameters.get("entry_id")
    if entry_id is None:
        return
    row = entry_for(context, entry_id, repository, settings)
    params = plan.parameters
    if plan.tool not in {"fls", "istat", "icat"}:
        raise ValidationError("Selected entries support directory browsing, metadata and extraction only.")
    if plan.tool == "fls":
        if row["kind"] != "directory" or row["parent"] is None or params.get("directory_inode") != row["address"]:
            raise ValidationError("Directory does not match the selected inventory entry.")
    elif params.get("metadata_address") != row["address"]:
        raise ValidationError("Metadata address does not match the selected inventory entry.")
    if plan.tool == "icat" and (row["kind"] != "file" or params.get("entry_name") != row["name"]
                                or params.get("recover_deleted") != bool(row["deleted"])):
        raise ValidationError("Extraction options do not match the selected file entry.")
    return row


def browse(run, repository, settings, *, directory=None, query="", kind="", state="", scope="directory", offset=0):
    if len(query) > 256 or kind not in {"", "file", "directory", "other"} or state not in {"", "allocated", "deleted", "reallocated"} or scope not in {"directory", "filesystem"}:
        raise ValidationError("Choose supported triage filters and a search of at most 256 characters.")
    with verified_index(run, repository, settings) as db:
        folder = db.execute("SELECT * FROM entries WHERE id=?", (directory,)).fetchone() if directory else None
        if directory and (not folder or folder["kind"] != "directory" or folder["parent"] is None):
            raise ValidationError("Choose a directory from this file inventory.")
        if folder and db.execute("SELECT count(*) FROM entries WHERE path=? AND kind='directory'", (folder["path"],)).fetchone()[0] > 1:
            raise ValidationError("Several directory entries share this path. Open a fresh directory listing for the selected metadata address.")
        parent = folder["path"] if folder else ""
        if folder and not run["plan"]["parameters"].get("recursive"):
            raise ValidationError("This listing is not recursive; build a recursive inventory to browse its directories.")
        conditions, values = [], []
        if scope == "directory":
            conditions.append("parent=?")
            values.append(parent)
        if query:
            conditions.append("instr(lower(path),lower(?))>0")
            values.append(query)
        if kind:
            conditions.append("kind=?")
            values.append(kind)
        if state:
            conditions.append({"allocated": "deleted=0", "deleted": "deleted=1", "reallocated": "reallocated=1"}[state])
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        total = db.execute("SELECT count(*) FROM entries" + where, values).fetchone()[0]
        offset = min(max(0, offset), max(0, (total - 1) // 100 * 100))
        rows = [dict(row) for row in db.execute("SELECT * FROM entries" + where + " ORDER BY kind='directory' DESC,name COLLATE NOCASE,id LIMIT 100 OFFSET ?", [*values, offset])]
        for row in rows:
            if row["kind"] == "directory":
                row["ambiguous_path"] = db.execute("SELECT count(*) FROM entries WHERE path=? AND kind='directory'", (row["path"],)).fetchone()[0] > 1
        counts = dict(db.execute("SELECT count(*) AS total,coalesce(sum(deleted),0) AS deleted,coalesce(sum(reallocated),0) AS reallocated FROM entries").fetchone())
        breadcrumbs = []
        if folder:
            for prefix in list(PurePosixPath(parent).parents)[::-1] + [PurePosixPath(parent)]:
                if str(prefix) == ".":
                    continue
                ancestor = db.execute("SELECT id,name FROM entries WHERE path=? AND kind='directory' AND parent IS NOT NULL ORDER BY id LIMIT 1", (str(prefix),)).fetchone()
                if ancestor:
                    breadcrumbs.append(dict(ancestor))
        return {"run_id": run["id"], "rows": rows, "total": total, "offset": offset, "counts": counts,
                "directory": directory, "location": parent or "/", "breadcrumbs": breadcrumbs,
                "query": query, "kind": kind, "state": state, "scope": scope,
                "recursive": bool(run["plan"]["parameters"].get("recursive")),
                "directory_inode": run["plan"]["parameters"].get("directory_inode"),
                "unparsed_lines": run["analysis"].get("unparsed_lines", 0),
                "deleted_only": bool(run["plan"]["parameters"].get("deleted_only"))}
