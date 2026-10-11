"""Case management, workflow pages and bounded result viewing."""
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, url_for
from .tool_base import normalize as normalize_path, allowed as is_path_allowed
from .zimmerman import resolve_ez_tool
from .volatility import discover as discover_volatility, BUNDLES
from .carving import available_types
from .tool_base import ValidationError
from .catalog import EZ_TOOL_ORDER
from .context import runtime_repository, runtime_settings
from .presentation import ARTIFACT_TYPES, detect_artifact_type, EZ_CATEGORIES
from .worker import ExecutionFailure, hash_file
from .workflow_catalog import WORKFLOWS, CATEGORIES
from .tool_base import executable
from .viewers import read_text_preview, parse_csv_table, parse_strings_table, parse_carving_audit, parse_bulk_extractor_feature, detect_text_table_format, parse_json_table

logger = logging.getLogger(__name__)
web = Blueprint("web", __name__)


def load_cases():
    return runtime_repository().cases()


def load_runs():
    return runtime_repository().runs()


def build_run_manifest(run, limit="configured"):
    if limit == "configured":
        limit = current_app.config["RESULT_FILE_LIMIT"]
    files = [entry for entry in runtime_repository().artifacts(run["id"])
             if is_path_allowed(entry["path"], runtime_settings().output_roots) and os.path.isfile(entry["path"])]
    return (files if limit is None else files[:limit]), limit is not None and len(files) > limit


def compute_sha256(path):
    return hash_file(path)[0]


def error_response(message, status=400):
    """Create a standardized JSON error response."""
    return jsonify({"error": message}), status


def slugify(value):
    cleaned = "".join(char if char.isalnum() else "-" for char in value.lower())
    return "-".join(filter(None, cleaned.split("-"))) or "case"


@web.after_app_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@web.route("/")
def index():
    return render_template("index.html")


@web.route("/file-carving")
def file_carving():
    return render_template("file_carving.html")


@web.route("/artifact-triage")
def artifact_triage():
    return render_template("artifact_triage.html")


@web.route("/artifact-timeline")
def artifact_timeline():
    cases = load_cases()
    return render_template("artifact_timeline.html", cases=cases)


def carving_page(tool):
    error = None
    try:
        types = available_types(tool, runtime_settings())
    except ValidationError as exc:
        types, error = [], str(exc)
    return render_template(tool + ".html", cases=load_cases(), carving_types=types, carving_error=error)


@web.route("/foremost")
def foremost():
    return carving_page("foremost")


@web.route("/memory")
def memory():
    return render_template("memory.html")


@web.route("/tools")
def tools():
    return render_template("tools.html")


@web.get("/disk-analysis")
@web.get("/file-examination")
def additional_tools():
    category = request.path.lstrip("/")
    entries = []
    for tool_id in CATEGORIES[category]:
        entry = dict(WORKFLOWS[tool_id])
        try:
            executable(tool_id, [tool_id], runtime_settings())
            entry["installed"] = True
        except ValueError:
            entry["installed"] = False
        entries.append(entry)
    return render_template("workflow_category.html", workflows=entries, title=entries[0]["category"])


@web.get("/workflow/<tool_id>")
def additional_workflow(tool_id):
    workflow = WORKFLOWS.get(tool_id)
    if not workflow:
        return error_response("Workflow not found.", 404)
    return render_template("workflow.html", cases=load_cases(), workflow=workflow)


@web.get("/run/<run_id>/analysis")
def workflow_analysis(run_id):
    run, error = run_or_error(run_id)
    if error:
        return error
    summary = run.get("analysis", {})
    table = None
    total = 0
    offset = max(0, request.args.get("offset", 0, type=int))
    examinations = []
    if summary.get("derived_file") and run["status"] == "success":
        target = os.path.join(run["output_path"], summary["derived_file"])
        if is_path_allowed(target, runtime_settings().output_roots):
            try:
                with open(target, "rb") as handle:
                    header = handle.read(1024)
                examinations = ["xxd"]
                if b"\x00" not in header:
                    examinations.append("head")
                if b"%PDF-" in header and summary.get("artifact_kind") == "extracted_file":
                    examinations += ["pdfinfo", "pdftotext"]
            except OSError:
                pass
    if summary.get("table"):
        target = os.path.join(run["output_path"], summary["table"])
        if not is_path_allowed(target, runtime_settings().output_roots):
            return error_response("Result is outside allowed roots.", 403)
        try:
            table, total, _ = parse_csv_table(target, row_limit=100, row_offset=offset)
        except (OSError, ValueError) as exc:
            return error_response(str(exc))
    files, truncated = build_run_manifest(run)
    derived_keys = {entry["path"]: "d:" + str(entry["id"]) for entry in runtime_repository().derived_inputs(run["case_id"])} if run.get("case_id") and request.args.get("workspace_input") else {}
    return render_template("workflow_analysis.html", run=run, summary=summary, table=table, total=total,
                           offset=offset, examinations=examinations, result_files=files, result_truncated=truncated,
                           workspace_input=request.args.get("workspace_input"), derived_keys=derived_keys)


@web.route("/guides")
def guides():
    return render_template("guides.html")


@web.route("/glossary")
def glossary():
    return render_template("glossary.html")


def get_tools_for_category(category):
    """Get tools filtered by category, with JSON-serializable version."""
    tools = []
    tools_json = []
    for tool_id in EZ_TOOL_ORDER:
        tool = resolve_ez_tool(tool_id, runtime_settings())
        if not tool or tool.get("category") != category:
            continue
        tools.append(tool)
        tools_json.append(
            {
                "id": tool["id"],
                "label": tool["label"],
                "summary": tool["summary"],
                "description": tool["description"],
                "input_hint": tool["input_hint"],
                "input_mode": tool["input_mode"],
                "installed": tool["installed"],
                "binary_display": tool["binary_display"],
                "version": tool["version"],
                "error": tool.get("error"),
                "options": tool["options"],
                "export_summary": tool["export_summary"],
                "rejected_maps": tool.get("rejected_maps", {}),
            }
        )
    return tools, tools_json


def get_all_ez_tools_grouped():
    """Get all EZ tools grouped by category for single-page display."""
    categories_with_tools = []
    all_tools_json = []

    for category in EZ_CATEGORIES:
        cat_id = category["id"]
        tools, tools_json = get_tools_for_category(cat_id)
        if tools:
            categories_with_tools.append(
                {
                    "id": cat_id,
                    "label": category["label"],
                    "description": category["description"],
                    "tools": tools,
                }
            )
            all_tools_json.extend(tools_json)

    return categories_with_tools, all_tools_json


@web.route("/eric-zimmerman")
def eric_zimmerman():
    cases = load_cases()
    categories, tools_json = get_all_ez_tools_grouped()
    return render_template(
        "eric_zimmerman.html",
        cases=cases,
        categories=categories,
        tools_json=tools_json,
    )


@web.route("/metadata-extraction")
def metadata_extraction():
    return render_template("metadata_extraction.html")


@web.route("/exiftool")
def exiftool():
    cases = load_cases()
    return render_template("exiftool.html", cases=cases)


@web.route("/strings")
def strings_tool():
    cases = load_cases()
    return render_template("strings.html", cases=cases)


@web.route("/filetype")
def filetype():
    cases = load_cases()
    return render_template("filetype.html", cases=cases)


@web.route("/volatility")
def volatility():
    try:
        installed = discover_volatility(runtime_settings())
        error = None
    except ValidationError as exc:
        installed = {"plugins": {}, "version": None, "symbol_paths": [], "import_failures": []}
        error = str(exc)
    groups = {os: {name: spec for name, spec in installed["plugins"].items() if spec["os"] == os}
              for os in ("windows", "linux", "mac", "general")}
    bundles = {os: [{"label": label, "plugins": [name for name in names if name in groups[os]
                    and not any(o["required"] for o in groups[os][name]["options"])]}
                   for label, names in BUNDLES[os]] for os in groups}
    return render_template("volatility.html", cases=load_cases(), installed=installed,
                           discovery_error=error, groups=groups, bundles=bundles,
                           symbol_roots=runtime_settings().symbol_roots)


@web.route("/bulk-extractor")
def bulk_extractor():
    cases = load_cases()
    return render_template("bulk_extractor.html", cases=cases)


@web.route("/scalpel")
def scalpel():
    return carving_page("scalpel")


@web.route("/cases", methods=["GET", "POST"])
def cases():
    if request.method == "POST":
        name = request.form.get("name", "").strip() or "Untitled case"
        source = request.form.get("source_path", "").strip()
        artifacts = []
        created_at = datetime.now(timezone.utc).isoformat()
        if source:
            source = normalize_path(source)
            if not is_path_allowed(source, runtime_settings().input_roots):
                return error_response("Evidence path is outside allowed input roots.", 403)
            if not os.path.isfile(source):
                return error_response("Initial evidence must be an existing regular file.")
            try:
                digest = compute_sha256(source)
            except (OSError, ExecutionFailure):
                return error_response("Unable to hash stable evidence.")
            artifacts.append({"id": uuid.uuid4().hex, "type": detect_artifact_type(source),
                              "type_basis": "filename_hint",
                              "path": source, "label": os.path.basename(source), "hash": digest,
                              "added_at": created_at})
        runtime_repository().add_case({"id": uuid.uuid4().hex, "name": name,
            "summary": request.form.get("summary", "").strip(), "slug": slugify(name),
            "created_at": created_at, "artifacts": artifacts})
        return redirect(url_for("web.cases"))

    cases = load_cases()
    runs = load_runs()
    runs_by_case = {}
    for run in runs:
        case_id = run.get("case_id")
        if not case_id:
            continue
        output_files, truncated = build_run_manifest(run)
        if output_files:
            run["result_files"] = output_files
            run["result_truncated"] = truncated
        tool = run.get("tool") or "unknown"
        runs_by_case.setdefault(case_id, {}).setdefault(tool, []).append(run)

    grouped_runs = {}
    for case_id, tool_map in runs_by_case.items():
        groups = []
        for tool, tool_runs in tool_map.items():
            tool_runs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
            groups.append({"tool": tool, "runs": tool_runs})
        groups.sort(key=lambda item: item["tool"])
        grouped_runs[case_id] = groups

    # Build artifact type labels for template
    artifact_type_labels = {k: v.get("label", k) for k, v in ARTIFACT_TYPES.items()}

    return render_template(
        "cases.html",
        cases=cases,
        runs_by_case=grouped_runs,
        artifact_type_labels=artifact_type_labels,
    )


@web.route("/case/<case_id>/results")
def case_results(case_id):
    """Aggregated results view for a case - shows all tool outputs in one place."""
    cases = load_cases()
    case = None
    for c in cases:
        if c.get("id") == case_id:
            case = c
            break

    if not case:
        return render_template(
            "case_results.html",
            case=None,
            error="Case not found.",
            runs=[],
            result_files=[],
            stats={},
        )

    case_runs = runtime_repository().runs(case_id=case_id)

    # Sort by date (newest first)
    case_runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    # Build result files from all runs
    all_result_files = []
    stats = {
        "total_runs": len(case_runs),
        "successful_runs": 0,
        "failed_runs": 0,
        "tools_used": set(),
        "total_files": 0,
    }

    for run in case_runs:
        tool = run.get("tool", "unknown")
        stats["tools_used"].add(tool)

        if run.get("status") == "success":
            stats["successful_runs"] += 1
        elif run.get("status") in {"error", "interrupted", "cancelled"}:
            stats["failed_runs"] += 1

        # Get result files for this run
        files, truncated = build_run_manifest(run, limit=None)
        for f in files:
            f["tool"] = tool
            f["run_id"] = run.get("id")
            f["run_status"] = run.get("status", "unknown")
            f["run_date"] = run.get("created_at", "")
            all_result_files.append(f)

        stats["total_files"] += len(files)

    stats["tools_used"] = list(stats["tools_used"])

    return render_template(
        "case_results.html",
        case=case,
        error="",
        runs=case_runs,
        result_files=all_result_files,
        stats=stats,
    )


@web.route("/api/case/<case_id>")
def get_case(case_id):
    """Get case details including artifacts."""
    cases = load_cases()
    for case in cases:
        if case.get("id") == case_id:
            return jsonify({"case": case})
    return jsonify({"error": "Case not found."}), 404


@web.get("/api/case/<case_id>/inputs")
def case_inputs(case_id):
    case = runtime_repository().case(case_id)
    if not case:
        return error_response("Case not found.", 404)
    values = list(case.get("artifacts", []))
    for entry in runtime_repository().derived_inputs(case_id):
        if not is_path_allowed(entry["path"], runtime_settings().output_roots) or not os.path.isfile(entry["path"]):
            continue
        values.append({"id": entry["id"], "path": entry["path"], "hash": entry["sha256"], "type": "derived_file",
                       "label": entry["name"], "source_run_id": entry["run_id"]})
    return jsonify(inputs=values)


@web.route("/api/case/<case_id>/artifacts", methods=["POST"])
def add_artifact(case_id):
    """Add an artifact to a case."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or any(not isinstance(payload.get(key, ""), str) for key in ("path", "type", "label")):
        return error_response("Artifact request must contain text fields in a JSON object.")
    artifact_path = payload.get("path", "").strip()
    artifact_type = payload.get("type", "").strip()
    label = payload.get("label", "").strip()

    if not artifact_path:
        return jsonify({"error": "Artifact path is required."}), 400

    normalized_path = normalize_path(artifact_path)
    if not is_path_allowed(normalized_path, runtime_settings().input_roots):
        return jsonify({"error": "Artifact path is outside allowed input roots."}), 403
    if not (os.path.isfile(normalized_path) or os.path.isdir(normalized_path)):
        return jsonify({"error": "Artifact path not found."}), 400

    cases = load_cases()
    case = None
    for c in cases:
        if c.get("id") == case_id:
            case = c
            break

    if not case:
        return jsonify({"error": "Case not found."}), 404

    type_basis = "analyst" if artifact_type else "filename_hint"
    # Auto-detect type if not provided
    if not artifact_type:
        artifact_type = detect_artifact_type(normalized_path)

    if artifact_type not in ARTIFACT_TYPES:
        return error_response("Unsupported artifact type.")

    # Use filename as label if not provided
    if not label:
        label = os.path.basename(normalized_path)

    # Compute hash for the artifact
    artifact_hash = ""
    if os.path.isfile(normalized_path):
        try:
            artifact_hash = compute_sha256(normalized_path)
        except (OSError, ExecutionFailure):
            return jsonify({"error": "Unable to hash a stable artifact."}), 400

    artifact = {
        "id": uuid.uuid4().hex,
        "type": artifact_type,
        "type_basis": type_basis,
        "path": normalized_path,
        "label": label,
        "hash": artifact_hash,
        "added_at": datetime.now(timezone.utc).isoformat(),
    }

    def append_artifact(current):
        current.setdefault("artifacts", []).append(artifact)

    runtime_repository().mutate_case(case_id, append_artifact)
    return jsonify({"success": True, "artifact": artifact})


@web.route("/api/case/<case_id>/artifacts/<artifact_id>", methods=["DELETE"])
def remove_artifact(case_id, artifact_id):
    """Remove an artifact from a case."""
    cases = load_cases()
    case = None
    for c in cases:
        if c.get("id") == case_id:
            case = c
            break

    if not case:
        return jsonify({"error": "Case not found."}), 404

    artifacts = case.get("artifacts", [])
    original_count = len(artifacts)
    case["artifacts"] = [a for a in artifacts if a.get("id") != artifact_id]

    if len(case["artifacts"]) == original_count:
        return jsonify({"error": "Artifact not found."}), 404

    runtime_repository().mutate_case(case_id, lambda current: current.update(
        artifacts=[a for a in current.get("artifacts", []) if a.get("id") != artifact_id]))
    return jsonify({"success": True})


@web.route("/api/artifact-types")
def get_artifact_types():
    """Get available artifact types for UI dropdowns."""
    types = []
    for key, info in ARTIFACT_TYPES.items():
        types.append({
            "id": key,
            "label": info.get("label", key),
            "icon": info.get("icon", "generic"),
        })
    return jsonify({"types": types})


@web.route("/api/case/<case_id>/search")
def case_search(case_id):
    """Search across all result files in a case."""
    query = request.args.get("q", "").strip().lower()
    file_type = request.args.get("type", "").strip().lower()
    tool_filter = request.args.get("tool", "").strip().lower()
    limit = request.args.get("limit", 100, type=int)
    limit = min(max(1, limit), 500)

    if not query:
        return jsonify({"error": "Search query required."}), 400

    cases = load_cases()
    case = None
    for c in cases:
        if c.get("id") == case_id:
            case = c
            break

    if not case:
        return jsonify({"error": "Case not found."}), 404

    case_runs = runtime_repository().runs(case_id=case_id)

    results = []
    files_searched = 0

    for run in case_runs:
        tool = run.get("tool", "unknown").lower()

        # Apply tool filter if specified
        if tool_filter and tool_filter not in tool:
            continue

        files, _ = build_run_manifest(run, limit=None)

        for f in files:
            file_path = f.get("path", "")
            file_name = f.get("name", "").lower()

            # Apply file type filter
            if file_type:
                if not file_name.endswith(f".{file_type}"):
                    continue

            # Skip non-text files
            if not file_name.endswith((".txt", ".csv", ".json", ".jsonl", ".log")):
                continue

            if not is_path_allowed(file_path, current_app.config["BROWSE_ROOTS"]):
                continue

            if not os.path.isfile(file_path):
                continue

            files_searched += 1

            # Search file contents
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                    line_num = 0
                    for line in handle:
                        line_num += 1
                        if query in line.lower():
                            results.append({
                                "file": f.get("name"),
                                "path": file_path,
                                "tool": run.get("tool"),
                                "line": line_num,
                                "content": line.strip()[:500],  # Truncate long lines
                            })

                            if len(results) >= limit:
                                break
                    if len(results) >= limit:
                        break
            except OSError:
                continue

        if len(results) >= limit:
            break

    return jsonify({
        "query": query,
        "results": results,
        "total": len(results),
        "truncated": len(results) >= limit,
        "files_searched": files_searched,
    })


def run_or_error(run_id):
    run = runtime_repository().run(run_id)
    if not run:
        return None, (jsonify(error="Run not found."), 404)
    return run, None


def read_run_log(run, max_bytes=1024 * 1024):
    path = run.get("log_path")
    if not path or not is_path_allowed(path, runtime_settings().output_roots):
        return None
    if not os.path.isfile(path) and run["status"] == "running":
        path = os.path.join(os.path.dirname(run["output_path"]), ".sifted-staging", run["id"], "run.log")
    if not os.path.isfile(path) or not is_path_allowed(path, runtime_settings().output_roots):
        return None
    with open(path, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        handle.seek(max(0, size - max_bytes))
        content = handle.read(max_bytes).decode("utf-8", errors="replace")
    return content, size > max_bytes


@web.get("/api/run/<run_id>/log")
def run_log(run_id):
    run, error = run_or_error(run_id)
    if error:
        return error
    log = read_run_log(run)
    return jsonify(log=log[0], truncated=log[1]) if log else (jsonify(error="Log not available."), 404)


@web.get("/api/run/<run_id>/tail")
def run_tail(run_id):
    run, error = run_or_error(run_id)
    if error:
        return error
    lines = max(1, min(request.args.get("lines", 5, type=int), 200))
    log = read_run_log(run, 65536)
    return jsonify(lines=log[0].splitlines(keepends=True)[-lines:]) if log else (jsonify(error="Log not available."), 404)


@web.get("/api/run/<run_id>/results")
def run_results(run_id):
    run, error = run_or_error(run_id)
    if error:
        return error
    files, truncated = build_run_manifest(run)
    return jsonify(files=files, truncated=truncated,
                   plugin_results=run.get("plugin_results", []),
                   analysis_url=url_for("web.workflow_analysis", run_id=run_id) if run.get("analysis") else None)


@web.route("/api/browse")
def browse():
    target = request.args.get("path") or current_app.config["BROWSE_ROOTS"][0]
    target = normalize_path(target)
    if not is_path_allowed(target, current_app.config["BROWSE_ROOTS"]):
        return jsonify({"error": "Access denied", "path": target}), 403

    if not os.path.isdir(target):
        return jsonify({"error": "Not a directory", "path": target}), 400

    entries = []
    try:
        with os.scandir(target) as it:
            for entry in it:
                if entry.name.startswith("."):
                    continue
                entries.append(
                    {
                        "name": entry.name,
                        "path": entry.path,
                        "type": "dir" if entry.is_dir() else "file",
                    }
                )
    except OSError:
        return jsonify({"error": "Unable to read directory", "path": target}), 400

    entries.sort(key=lambda item: (item["type"] != "dir", item["name"].lower()))
    parent = os.path.dirname(target) if target != os.path.dirname(target) else None
    if parent and not is_path_allowed(parent, current_app.config["BROWSE_ROOTS"]):
        parent = None

    return jsonify({"path": target, "parent": parent, "entries": entries})


@web.route("/view-file")
def view_file():
    target = request.args.get("path", "")
    view_param = request.args.get("view", "").strip().lower()

    # Determine if file supports table view
    lower_target = target.lower() if target else ""
    is_json = lower_target.endswith((".json", ".jsonl"))
    is_csv = lower_target.endswith(".csv")
    is_txt = lower_target.endswith(".txt")

    # Detect text file format for table parsing
    text_format = None
    if is_txt and target and is_path_allowed(target, current_app.config["BROWSE_ROOTS"]):
        try:
            text_format = detect_text_table_format(target)
        except Exception:
            text_format = None

    table_available = is_json or is_csv or bool(text_format)

    # Default to table view for structured data, raw for others
    if view_param:
        view_mode = view_param
    else:
        view_mode = "table" if table_available else "raw"

    if not target:
        return render_template(
            "file_viewer.html",
            path="",
            content="",
            truncated=False,
            error="Missing file path.",
            view_mode=view_mode,
            table_available=False,
            table_error="",
            table_data=None,
            table_total=0,
            table_truncated=False,
        )

    target = normalize_path(target)
    lower_target = target.lower()
    is_json = lower_target.endswith((".json", ".jsonl"))
    is_csv = lower_target.endswith(".csv")
    is_txt = lower_target.endswith(".txt")

    # Re-detect text format after normalization
    text_format = None
    if is_txt and is_path_allowed(target, current_app.config["BROWSE_ROOTS"]):
        try:
            text_format = detect_text_table_format(target)
        except Exception:
            text_format = None

    table_available = is_json or is_csv or bool(text_format)

    # Re-evaluate default view mode after path normalization
    if not view_param:
        view_mode = "table" if table_available else "raw"

    if not is_path_allowed(target, current_app.config["BROWSE_ROOTS"]):
        return render_template(
            "file_viewer.html",
            path=target,
            content="",
            truncated=False,
            error="Access denied.",
            view_mode=view_mode,
            table_available=table_available,
            table_error="",
            table_data=None,
            table_total=0,
            table_truncated=False,
        )
    if not os.path.isfile(target):
        return render_template(
            "file_viewer.html",
            path=target,
            content="",
            truncated=False,
            error="File not found.",
            view_mode=view_mode,
            table_available=table_available,
            table_error="",
            table_data=None,
            table_total=0,
            table_truncated=False,
        )

    table_data = None
    table_error = ""
    table_total = 0
    table_truncated = False

    if view_mode == "table":
        if not table_available:
            table_error = "Table view is only available for JSON, CSV, and supported text files."
        else:
            try:
                # Load initial 100 rows for virtual scroll (50 per batch after)
                if is_csv:
                    table_data, table_total, table_truncated = parse_csv_table(target, row_limit=100)
                elif is_json:
                    table_data, table_total, table_truncated = parse_json_table(target, row_limit=100)
                elif text_format == "strings":
                    table_data, table_total, table_truncated = parse_strings_table(target, row_limit=100)
                elif text_format == "carving_audit":
                    table_data, table_total, table_truncated = parse_carving_audit(target, row_limit=100)
                elif text_format == "bulk_extractor":
                    table_data, table_total, table_truncated = parse_bulk_extractor_feature(target, row_limit=100)
                else:
                    table_error = "Unable to parse file as table."
            except (ValueError, json.JSONDecodeError) as exc:
                table_error = str(exc)
            except OSError:
                table_error = "Unable to read file."

    content = ""
    truncated = False
    if view_mode != "table" or table_error:
        try:
            content, truncated = read_text_preview(target)
        except OSError:
            return render_template(
                "file_viewer.html",
                path=target,
                content="",
                truncated=False,
                error="Unable to read file.",
                view_mode=view_mode,
                table_available=table_available,
                table_error=table_error,
                table_data=table_data,
                table_total=table_total,
                table_truncated=table_truncated,
            )

    return render_template(
        "file_viewer.html",
        path=target,
        content=content,
        truncated=truncated,
        error="",
        view_mode=view_mode,
        table_available=table_available,
        table_error=table_error,
        table_data=table_data,
        table_total=table_total,
        table_truncated=table_truncated,
    )


@web.route("/api/table-rows")
def api_table_rows():
    """API endpoint for virtual scroll - returns batches of table rows."""
    target = request.args.get("path", "")
    offset = request.args.get("offset", 0, type=int)
    limit = request.args.get("limit", 50, type=int)

    # Clamp values
    offset = max(0, offset)
    limit = min(max(1, limit), 200)  # Max 200 rows per request

    if not target:
        return jsonify({"error": "Missing file path."}), 400

    target = normalize_path(target)
    lower_target = target.lower()
    is_json = lower_target.endswith((".json", ".jsonl"))
    is_csv = lower_target.endswith(".csv")
    is_txt = lower_target.endswith(".txt")

    # Detect text file format
    text_format = None
    if is_txt and is_path_allowed(target, current_app.config["BROWSE_ROOTS"]):
        try:
            text_format = detect_text_table_format(target)
        except Exception:
            text_format = None

    if not (is_json or is_csv or text_format):
        return jsonify({"error": "Only JSON, CSV, and supported text files allowed."}), 400

    if not is_path_allowed(target, current_app.config["BROWSE_ROOTS"]):
        return jsonify({"error": "Access denied."}), 403

    if not os.path.isfile(target):
        return jsonify({"error": "File not found."}), 404

    try:
        # Parse window for the requested offset/limit while counting full rows.
        if is_csv:
            table_data, total_rows, _ = parse_csv_table(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif is_json:
            table_data, total_rows, _ = parse_json_table(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif text_format == "strings":
            table_data, total_rows, _ = parse_strings_table(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif text_format == "carving_audit":
            table_data, total_rows, _ = parse_carving_audit(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif text_format == "bulk_extractor":
            table_data, total_rows, _ = parse_bulk_extractor_feature(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        else:
            return jsonify({"error": "Unable to parse file format."}), 400

        sliced_rows = table_data.get("rows", [])

        return jsonify({
            "columns": table_data.get("columns", []),
            "rows": sliced_rows,
            "offset": offset,
            "limit": limit,
            "total": total_rows,
            "has_more": offset + len(sliced_rows) < total_rows,
        })
    except (ValueError, json.JSONDecodeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except OSError:
        return jsonify({"error": "Unable to read file."}), 500


