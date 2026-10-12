"""Evidence intake and resumable, bounded transfers into managed storage."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import uuid

from flask import Blueprint, current_app, jsonify, request

from .context import runtime_repository, runtime_settings
from .evidence_intake import enqueue_intake, metadata
from .integrity import evidence_path
from .storage import StoreError, utc_now
from .tool_base import ValidationError, allowed

intake = Blueprint("intake", __name__)
CHUNK_BYTES = 4 * 1024 * 1024


@intake.before_request
def bound_request():
    request.max_content_length = CHUNK_BYTES if request.method == "PUT" else 1024 * 1024


@intake.errorhandler(ValidationError)
@intake.errorhandler(StoreError)
@intake.errorhandler(ValueError)
def invalid(exc):
    return jsonify(error=str(exc)), 400


@intake.errorhandler(OSError)
def io_error(exc):
    current_app.logger.exception("Evidence storage operation failed")
    return jsonify(error="Evidence storage is unavailable. Check workstation space and permissions; retry to resume."), 503


def evidence(case_id, evidence_id):
    case = runtime_repository().case(case_id)
    item = next((x for x in (case or {}).get("artifacts", []) if x["id"] == evidence_id), None)
    if not item:
        raise ValidationError("Evidence not found in this case.")
    return item


@intake.post("/api/case/<case_id>/artifacts")
def register(case_id):
    return jsonify(enqueue_intake(runtime_repository(), runtime_settings(), case_id, request.get_json(silent=True))), 202


@intake.post("/api/case/<case_id>/evidence/<evidence_id>/verify")
def verify(case_id, evidence_id):
    evidence(case_id, evidence_id)
    return jsonify(enqueue_intake(runtime_repository(), runtime_settings(), case_id, {}, evidence_id)), 202


@intake.delete("/api/case/<case_id>/artifacts/<evidence_id>")
def retire(case_id, evidence_id):
    runtime_repository().change_evidence(case_id, evidence_id, {"status": "retired", "retired_at": utc_now()}, "retired", {})
    return jsonify(success=True)


@intake.get("/api/case/<case_id>/evidence/<evidence_id>/custody")
def custody(case_id, evidence_id):
    item = evidence(case_id, evidence_id)
    response = jsonify(evidence=item, custody=runtime_repository().custody(case_id, evidence_id))
    response.headers["Content-Disposition"] = f'attachment; filename="evidence-{item["id"]}-custody.json"'
    return response


def save_upload(session):
    with runtime_repository().connection() as db:
        db.execute("UPDATE evidence_uploads SET data=? WHERE id=?", (json.dumps(session), session["id"]))


def upload(case_id, upload_id):
    with runtime_repository().connection() as db:
        row = db.execute("SELECT data FROM evidence_uploads WHERE id=? AND case_id=?", (upload_id, case_id)).fetchone()
    if not row:
        raise ValidationError("Upload not found in this case.")
    return json.loads(row[0])


def upload_root(session):
    root = Path(session["root"])
    if evidence_path(root) != str(root) or not allowed(root, runtime_settings().input_roots) or root.parent.name != ".sifted-evidence":
        raise ValidationError("Managed upload storage changed or is no longer allowed.")
    return root


@contextmanager
def locked_upload(case_id, upload_id):
    session = upload(case_id, upload_id)
    root = upload_root(session)
    fd = os.open(root / "transfer.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield upload(case_id, upload_id), root


def upload_view(session):
    root = upload_root(session)
    return {"id": session["id"], "status": session["status"], "chunk_bytes": CHUNK_BYTES,
            "files": [{**entry, "offset": (root / "files" / entry["name"]).stat().st_size if session["status"] != "discarded" else 0}
                      for entry in session["files"]], "intake": session.get("intake")}


@intake.post("/api/case/<case_id>/uploads")
def start_upload(case_id):
    repo = runtime_repository()
    if not repo.case(case_id):
        raise ValidationError("Case not found.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.keys() - {"files", "primary", "metadata"}:
        raise ValidationError("Upload requires files, an optional primary index, and intake metadata.")
    entries = data.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 1024:
        raise ValidationError("Select from 1 to 1024 files per evidence collection.")
    names, total = set(), 0
    for entry in entries:
        if not isinstance(entry, dict) or entry.keys() != {"name", "size"}:
            raise ValidationError("Each upload file needs a name and size.")
        name, size = entry["name"], entry["size"]
        if (not isinstance(name, str) or not name or name in {".", ".."} or name in names or len(name.encode()) > 255
                or any(c in name for c in '/\\') or any(ord(c) < 32 for c in name)):
            raise ValidationError("Upload filenames must be unique safe names without directory components.")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValidationError("Upload sizes must be nonnegative integers.")
        names.add(name)
        total += size
    if total > current_app.config["MAX_EVIDENCE_UPLOAD_BYTES"]:
        raise ValidationError("Evidence exceeds the configured upload size limit. Use a workstation path for larger evidence.")
    primary = data.get("primary", 0 if len(entries) == 1 else None)
    if primary is not None and (isinstance(primary, bool) or not isinstance(primary, int) or not 0 <= primary < len(entries)):
        raise ValidationError("Choose the primary file or upload as a collected directory.")
    info = metadata(data.get("metadata", {}))
    if info.get("path"):
        raise ValidationError("Upload paths are assigned by the workstation.")
    upload_id = uuid.uuid4().hex
    root = Path(runtime_settings().input_roots[0]) / ".sifted-evidence" / upload_id
    evidence_path(root)
    root.mkdir(parents=True, mode=0o700)
    (root / "files").mkdir(mode=0o700)
    try:
        for entry in entries:
            fd = os.open(root / "files" / entry["name"], os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        session = {"id": upload_id, "case_id": case_id, "root": str(root), "files": entries, "primary": primary,
                   "metadata": info, "created_at": utc_now(), "status": "uploading"}
        with repo.connection() as db:
            db.execute("INSERT INTO evidence_uploads VALUES (?,?,?)", (upload_id, case_id, json.dumps(session)))
    except BaseException:
        shutil.rmtree(root)
        raise
    return jsonify(upload_view(session)), 201


@intake.get("/api/case/<case_id>/uploads/<upload_id>")
def upload_status(case_id, upload_id):
    return jsonify(upload_view(upload(case_id, upload_id)))


@intake.put("/api/case/<case_id>/uploads/<upload_id>/<int:index>")
def upload_chunk(case_id, upload_id, index):
    request.max_content_length = CHUNK_BYTES
    chunk = request.get_data(cache=False)
    try:
        offset = int(request.headers.get("Upload-Offset", ""))
    except ValueError:
        raise ValidationError("Upload-Offset must be a byte offset.")
    with locked_upload(case_id, upload_id) as (session, root):
        if session["status"] != "uploading" or index >= len(session["files"]) or offset < 0 or not chunk:
            raise ValidationError("Invalid upload state, file, offset or empty chunk.")
        entry = session["files"][index]
        path = root / "files" / entry["name"]
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(fd, "r+b") as handle:
            size = os.fstat(handle.fileno()).st_size
            if offset > size or offset + len(chunk) > entry["size"]:
                return jsonify(error="Upload offset or size does not match the transfer.", offset=size), 409
            handle.seek(offset)
            existing = handle.read(min(len(chunk), size - offset))
            if existing != chunk[:len(existing)]:
                return jsonify(error="Retried bytes differ from those already received. Start a new upload.", offset=size), 409
            handle.seek(offset + len(existing))
            handle.write(chunk[len(existing):])
            handle.flush()
            os.fsync(handle.fileno())
            offset = os.fstat(handle.fileno()).st_size
    return jsonify(offset=offset)


@intake.post("/api/case/<case_id>/uploads/<upload_id>/complete")
def complete_upload(case_id, upload_id):
    with locked_upload(case_id, upload_id) as (session, root):
        if session.get("intake"):
            return jsonify(session["intake"]), 202
        if session["status"] != "uploading":
            raise ValidationError("Upload is not available for intake.")
        for entry in session["files"]:
            path = root / "files" / entry["name"]
            evidence_path(path)
            if path.stat().st_size != entry["size"]:
                raise ValidationError("Upload is incomplete: " + entry["name"])
        source = root / "files"
        if session["primary"] is not None:
            source /= session["files"][session["primary"]]["name"]
            # Every uploaded byte must participate in the evidence manifest.
            from .evidence_intake import related_sources
            dependencies = related_sources(str(source))[1]
            if {str(root / "files" / e["name"]) for e in session["files"]} != {str(source), *dependencies}:
                raise ValidationError("Selected files are not a single image/companion set. Choose collected directory for unrelated files.")
        for entry in session["files"]:
            (root / "files" / entry["name"]).chmod(0o400)
        repo = runtime_repository()
        # A crash after queue commit but before saving the response is safe to retry.
        existing = next((x for x in repo.case(case_id).get("artifacts", []) if x["path"] == str(source)), None)
        if existing:
            result = {"success": True, "artifact": existing, "run_id": existing["intake_run_id"], "status": "queued"}
        else:
            result = enqueue_intake(repo, runtime_settings(), case_id, {**session["metadata"], "path": str(source),
                                    "source": session["metadata"].get("source") or "Browser upload"})
        session.update(status="queued", intake=result, completed_at=utc_now())
        save_upload(session)
    return jsonify(result), 202


@intake.delete("/api/case/<case_id>/uploads/<upload_id>")
def discard_upload(case_id, upload_id):
    with locked_upload(case_id, upload_id) as (session, root):
        if session["status"] != "uploading":
            raise ValidationError("Only unfinished transfers can be discarded.")
        shutil.rmtree(root / "files")
        session.update(status="discarded", discarded_at=utc_now())
        save_upload(session)
    return jsonify(success=True)
