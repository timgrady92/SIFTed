"""One durable intake operation for workstation paths, uploads and tool inputs."""
import re
import uuid
from pathlib import Path

from .disk_tools import image_sources
from .integrity import evidence_path
from .presentation import ARTIFACT_TYPES
from .storage import utc_now
from .tool_base import Plan, ToolAdapter, ValidationError, allowed, directory_members, signature


class IntakeAdapter(ToolAdapter):
    tool_id = "evidence-intake"
    source_kind = "file_or_dir"

    def build(self, payload, source, output, settings, preview=False):
        return Plan(self.tool_id, source, output, operation="evidence-intake", create_output_directory=True,
                    max_output_bytes=settings.max_output_bytes)


def metadata(payload):
    fields = {"path", "type", "label", "custodian", "source", "notes", "expected_sha256"}
    if not isinstance(payload, dict) or payload.keys() - fields or any(not isinstance(v, str) for v in payload.values()):
        raise ValidationError("Evidence intake requires supported text fields.")
    result = {k: v if k == "path" else v.strip() for k, v in payload.items()}
    if any(len(v) > 4096 for v in result.values()):
        raise ValidationError("Evidence intake fields must be at most 4096 characters.")
    if result.get("type") and result["type"] not in ARTIFACT_TYPES:
        raise ValidationError("Unsupported evidence type.")
    digest = result.get("expected_sha256", "").lower()
    if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValidationError("Expected SHA-256 must contain 64 hexadecimal characters.")
    result["expected_sha256"] = digest
    result["custodian"] = result.get("custodian") or "Unattributed"
    return result


def related_sources(source):
    """Discover native implicit dependencies; naming groups parts, not formats."""
    path = Path(source)
    if path.is_dir():
        return [], []
    with path.open("rb") as handle:
        header = handle.read(16)
    images = []
    if header.startswith((b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00")) or path.suffix in {".000", ".001"}:
        images = image_sources(source)
    dependencies = images[1:]
    if header.startswith(b"regf"):
        dependencies += [str(p) for p in path.parent.iterdir() if p.name.casefold() in {path.name.casefold() + x for x in (".log", ".log1", ".log2")}]
    if header == b"SQLite format 3\0":
        dependencies += [source + suffix for suffix in ("-wal", "-shm", "-journal") if Path(source + suffix).exists()]
    return images, sorted(set(dependencies))


def snapshot(source, settings):
    try:
        source = evidence_path(source)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if not allowed(source, settings.input_roots):
        raise ValidationError("Evidence path is outside allowed input roots.")
    path = Path(source)
    if not (path.is_file() or path.is_dir()):
        raise ValidationError("Evidence must be an existing regular file or directory.")
    record = {"path": source, "kind": "directory" if path.is_dir() else "file", "signature": signature(source),
              "artifact_id": None, "baseline_sha256": None}
    if path.is_dir():
        record["members"] = directory_members(source)
    else:
        images, dependencies = related_sources(source)
        if images:
            record["image_paths"] = images
        record["dependency_paths"] = dependencies
        record["related_files"] = []
        for member in dependencies:
            evidence_path(member)
            if not allowed(member, settings.input_roots) or not Path(member).is_file():
                raise ValidationError("Related evidence must be a regular file inside input roots.")
            record["related_files"].append({"path": member, "signature": signature(member)})
    return record


def enqueue_intake(repo, settings, case_id, payload, evidence_id=None):
    data = metadata(payload)
    case = repo.case(case_id)
    if not case:
        raise ValidationError("Case not found.")
    if evidence_id:
        item = next((x for x in case.get("artifacts", []) if x["id"] == evidence_id), None)
        if not item:
            raise ValidationError("Evidence not found.")
        data["path"] = item["path"]
    if not data.get("path"):
        raise ValidationError("Evidence path is required.")
    record = snapshot(data["path"], settings)
    if not evidence_id and any(x.get("path") == record["path"] for x in case.get("artifacts", [])):
        raise ValidationError("Evidence is already registered. Open its overview to verify it again.")
    run_id = uuid.uuid4().hex
    output = str(Path(settings.output_roots[0]) / ".sifted-intake" / run_id)
    if Path(record["path"]) == Path(output) or Path(record["path"]) in Path(output).parents:
        raise ValidationError("Register a collection below the input root, separate from intake reports.")
    plan = IntakeAdapter().build({}, record["path"], output, settings)
    record.update(case_id=case_id, registration=data)
    run = {"id": run_id, "tool": plan.tool, "case_id": case_id, "source_path": plan.source,
           "output_path": output, "log_path": output + ".log", "status": "queued", "created_at": utc_now(),
           "command": "", "parameters": {}, "plan": plan.to_dict()}
    repo.enqueue(run, record)
    artifact = next(x for x in repo.case(case_id)["artifacts"] if x["id"] == record["artifact_id"])
    return {"success": True, "artifact": artifact, "run_id": run_id, "status": "queued"}
