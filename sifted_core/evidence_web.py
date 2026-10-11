"""An integrated evidence workspace over the native adapters and durable queue."""

import os
import stat

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from .context import runtime_repository, runtime_settings
from .evidence_workspace import identify, partition_choices, resolve_actions, select_input, validate_context, workspace_inputs
from .presentation import ARTIFACT_TYPES
from .storage import StoreError
from .tool_base import Plan, ValidationError, allowed, executable, normalize
from .terminal import recipe
from .file_triage import browse
from .workflow_catalog import WORKFLOWS


evidence = Blueprint("evidence", __name__)


@evidence.errorhandler(ValidationError)
@evidence.errorhandler(StoreError)
def invalid(exc):
    return jsonify(error=str(exc)), 404 if str(exc) == "Case not found." else 400


def case_or_error(case_id):
    case = runtime_repository().case(case_id)
    if not case:
        raise StoreError("Case not found.")
    return case


@evidence.get("/evidence")
def evidence_home():
    return render_template("evidence_workspace.html", cases=runtime_repository().cases(), workspace=None)


def tool_reason(tool):
    try:
        executable(tool, [tool], runtime_settings())
    except ValidationError as exc:
        return str(exc)
    return None


def input_payload(item, case_id):
    return {"case_id": case_id, "source_path": item["path"], "workspace_input": item["key"]}


def disk_journey(selected, observed, runs, partitions, case_id, key):
    """Derive preparation and native action payloads from successful, matching runs."""
    successful = [run for run in runs if run["status"] == "success" and selected.get("hash") == run.get("input_sha256")]
    geometries = {(p["offset_sector"], p["sector_size"]): dict(p) for p in partitions}
    for run in successful:
        if run["tool"] in {"fsstat", "fls"}:
            params = run["plan"]["parameters"]
            geometry = (params.get("offset_sector", 0), params.get("sector_size"))
            geometries.setdefault(geometry, {"offset_sector": geometry[0], "sector_size": geometry[1], "description": "Examined filesystem"})
    if observed["kind"] == "filesystem" and not geometries:
        geometries[(0, None)] = {"offset_sector": 0, "sector_size": None, "description": "Filesystem image"}
    mapping = next((run for run in successful if run["tool"] == "mmls"), None)
    cards = []
    for geometry, card in geometries.items():
        matching = [run for run in successful if run["tool"] in {"fsstat", "fls"}
                    and (run["plan"]["parameters"].get("offset_sector", 0), run["plan"]["parameters"].get("sector_size")) == geometry]
        stat = next((run for run in matching if run["tool"] == "fsstat"), None)
        inventory = next((run for run in matching if run["tool"] == "fls" and run.get("analysis", {}).get("inventory")
                          and run["plan"]["parameters"].get("recursive")
                          and not run["plan"]["parameters"].get("directory_inode")
                          and not run["plan"]["parameters"].get("deleted_only")), None)
        context = inventory or stat
        params = {**input_payload(selected, case_id), "offset_sector": geometry[0], "sector_size": geometry[1]}
        if context:
            params["context_run_id"] = context["id"]
        elif mapping and geometry in {(p["offset_sector"], p["sector_size"]) for p in partitions}:
            params["context_run_id"] = mapping["id"]
        card.update(stat_payload=params, inventory_payload={**params, "recursive": True},
                    stat_run_id=stat["id"] if stat else None, inventory_run_id=inventory["id"] if inventory else None,
                    stat_reason=tool_reason("fsstat"), inventory_reason=tool_reason("fls"),
                    entry_count=inventory["analysis"]["entry_count"] if inventory else 0,
                    triage_url=url_for("evidence.case_workspace", case_id=case_id, input=key, tab="triage", context_run_id=inventory["id"]) if inventory else None,
                    blocks=[{"tool": tool, "label": label, "payload": params, "reason": tool_reason(tool),
                             "fields": [f for f in WORKFLOWS[tool]["fields"] if f["name"] not in {"offset_sector", "sector_size"}]}
                            for tool, label in (("blkstat", "Check block allocation"), ("blkcat", "Read a block"), ("blkls", "Sample unallocated blocks"), ("blkcalc", "Map a block address"))] if context else [])
        cards.append(card)
    return cards


def triage_view(context, selected, case_id, key, runs, inputs):
    if not context or context["tool"] != "fls":
        return None
    try:
        directory = request.args.get("directory", type=int)
        if request.args.get("directory") and (directory is None or directory < 1):
            raise ValidationError("Choose a directory from this file inventory.")
        result = browse(context, runtime_repository(), runtime_settings(), directory=directory,
                        query=request.args.get("q", ""), kind=request.args.get("kind", ""), state=request.args.get("state", ""),
                        scope=request.args.get("scope", "directory"), offset=request.args.get("offset", 0, type=int))
    except ValidationError as exc:
        return {"error": str(exc)}
    navigation = {"case_id": case_id, "input": key, "tab": "triage", "context_run_id": context["id"]}
    result.update(metadata_reason=tool_reason("istat"), extract_reason=tool_reason("icat"))
    result["selected_entry"] = request.args.get("entry", type=int)
    # Reopening an entry reuses its recorded work, scoped to this exact inventory
    # and source hash. An address alone is not an entry identity.
    completed = {}
    for run in runs:
        params = run["plan"]["parameters"]
        if (run["status"] == "success" and run.get("input_sha256") == selected.get("hash")
                and params.get("context_run_id") == context["id"] and params.get("entry_id")):
            completed.setdefault((run["tool"], params["entry_id"]), run["id"])
    captures = {item["source_run_id"]: item for item in inputs if item["origin"] == "derived"}
    filters = {"directory": directory, "q": result["query"], "kind": result["kind"], "state": result["state"], "scope": result["scope"]}
    result["root_url"] = url_for("evidence.case_workspace", **navigation)
    for crumb in result["breadcrumbs"]:
        crumb["url"] = url_for("evidence.case_workspace", directory=crumb["id"], **navigation)
    result["previous_url"] = url_for("evidence.case_workspace", offset=max(0, result["offset"] - 100), **navigation, **filters) if result["offset"] else None
    result["next_url"] = url_for("evidence.case_workspace", offset=result["offset"] + 100, **navigation, **filters) if result["offset"] + len(result["rows"]) < result["total"] else None
    geometry = {name: context["plan"]["parameters"][name] for name in ("offset_sector", "sector_size") if name in context["plan"]["parameters"]}
    for row in result["rows"]:
        row["metadata_run_id"] = completed.get(("istat", row["id"]))
        capture = captures.get(completed.get(("icat", row["id"])))
        row["captured_key"] = capture["key"] if capture else None
        params = {**input_payload(selected, case_id), "context_run_id": context["id"], "entry_id": row["id"], **geometry}
        row["metadata_payload"] = {**params, "metadata_address": row["address"]}
        if row["kind"] == "directory" and row["parent"] is not None:
            if result["recursive"] and not row["ambiguous_path"]:
                row["directory_url"] = url_for("evidence.case_workspace", directory=row["id"], **navigation)
            else:
                row["listing_payload"] = {**params, "directory_inode": row["address"], "recursive": True}
        if row["kind"] == "file" and row["name"] not in {"", ".", "..", "_sifted"} and "\\" not in row["name"]:
            row["extract_payload"] = {**params, "metadata_address": row["address"], "entry_name": row["name"], "recover_deleted": bool(row["deleted"])}
    return result


def workspace_actions(selected, observed, runs, case_id, context=None):
    values = resolve_actions(selected, observed, runtime_settings(), runs, context)
    for action in values:
        action["payload"] = {**input_payload(selected, case_id), **action["parameters"]}
        action["fields"] = [field for field in WORKFLOWS.get(action["tool"], {}).get("fields", [])
                            if field["name"] not in action["parameters"]]
        # Advanced standalone entry points remain available for A/B evaluation.
        endpoint = {"volatility": "web.volatility", "foremost": "web.foremost", "scalpel": "web.scalpel",
                    "artifact-triage": "web.artifact_timeline", "bulk-extractor": "web.bulk_extractor"}.get(action["tool"])
        if endpoint:
            action["url"] = url_for(endpoint, **action["payload"])
    return values


def workspace(case_id):
    repo, settings = runtime_repository(), runtime_settings()
    case = case_or_error(case_id)
    inputs = workspace_inputs(case, repo)
    key = request.args.get("input", inputs[0]["key"] if inputs else "")
    selected = select_input(case, repo, key) if key else None
    parent_input = None
    if selected and selected["origin"] == "derived":
        producer = repo.run(selected["source_run_id"])
        parent_input = next((item for item in inputs if normalize(item["path"]) == normalize(producer["source_path"])), None)
        if parent_input:
            parent_input = {**parent_input, "url": url_for("evidence.case_workspace", case_id=case_id, input=parent_input["key"])}
    observed = identify(selected, settings) if selected else None
    runs = sorted(repo.runs(case_id=case_id), key=lambda r: r["created_at"], reverse=True)
    context_id = request.args.get("context_run_id", "")
    context = validate_context(repo.run(context_id), selected, case_id) if context_id and selected else None
    selected_runs = [r for r in runs if selected and normalize(r["source_path"]) == normalize(selected["path"])]
    actions = workspace_actions(selected, observed, runs, case_id, context) if selected else []
    maps = [r for r in selected_runs if r["tool"] == "mmls" and r["status"] == "success"
            and selected.get("hash") == r.get("input_sha256")]
    partitions = partition_choices(maps[0], repo, settings) if maps else []
    if maps and maps[0].get("analysis", {}).get("sector_size") in {512, 1024, 2048, 4096}:
        mapping = next(action for action in actions if action["id"] == "mmls")
        mapping["payload"]["sector_size"] = maps[0]["analysis"]["sector_size"]
    is_disk = bool(observed and observed["kind"] in {"disk", "filesystem", "ewf", "container"})
    tab = request.args.get("tab", "analysis")
    if tab not in {"overview", "analysis", "triage", "derived", "activity"}:
        raise ValidationError("Choose an available workspace tab.")
    if not is_disk and selected and tab == "triage":
        raise ValidationError("Filesystem triage requires disk or filesystem evidence.")
    journey = disk_journey(selected, observed, selected_runs, partitions, case_id, key) if is_disk else []
    if tab == "triage" and not context:
        inventories = [card for card in journey if card["inventory_run_id"]]
        if len(inventories) == 1:
            context = validate_context(repo.run(inventories[0]["inventory_run_id"]), selected, case_id)
    triage = triage_view(context, selected, case_id, key, selected_runs, inputs) if tab == "triage" and selected else None
    derived = []
    descendants = {normalize(selected["path"])} if selected else set()
    by_run = {run["id"]: run for run in runs}
    pending = [item for item in inputs if item["origin"] == "derived"]
    while pending:
        found = [item for item in pending if normalize(by_run[item["source_run_id"]]["source_path"]) in descendants]
        if not found:
            break
        derived.extend(found)
        descendants.update(normalize(item["path"]) for item in found)
        found_keys = {item["key"] for item in found}
        pending = [item for item in pending if item["key"] not in found_keys]
    input_offset = max(0, request.args.get("input_offset", 0, type=int))
    result = {"case": case, "inputs": inputs[input_offset:input_offset + 100], "input_offset": input_offset,
            "input_count": len(inputs), "selected": selected, "observed": observed, "actions": actions,
            "runs": selected_runs[:50], "run_count": len(selected_runs), "parent_input": parent_input,
            "context": context, "types": ARTIFACT_TYPES, "partitions": partitions,
            "is_disk": is_disk, "tab": tab, "journey": journey, "triage": triage, "derived": derived,
            "completed_count": sum(r["status"] == "success" for r in selected_runs),
            "active_count": sum(r["status"] in {"running", "queued"} for r in selected_runs)}
    examination_key = request.args.get("examine", "")
    item = next((item for item in derived if item["key"] == examination_key), None)
    if examination_key and not item:
        raise ValidationError("Choose a captured file from this evidence.")
    result["examination"] = None
    if item:
        observed_file = identify(item, settings)
        result["examination"] = {"input": item, "observed": observed_file,
                                 "actions": workspace_actions(item, observed_file, runs, case_id)}
    paths = {normalize(selected["path"])} if selected else set()
    paths.update(normalize(item["path"]) for item in derived)
    activity = [run for run in runs if normalize(run["source_path"]) in paths]
    result["activity"] = activity[:100]
    result["activity_count"] = len(activity)
    result["active"] = [{"runId": run["id"], "tool": run["tool"],
                         "payload": {"source_path": run["source_path"], **run["plan"]["parameters"]}}
                        for run in activity if run["status"] in {"queued", "running"}]
    return result


@evidence.get("/case/<case_id>/workspace")
def case_workspace(case_id):
    return render_template("evidence_workspace.html", cases=runtime_repository().cases(), workspace=workspace(case_id))


@evidence.get("/api/case/<case_id>/workspace")
def workspace_api(case_id):
    return jsonify(workspace(case_id))


@evidence.get("/api/case/<case_id>/workspace/view")
def workspace_view(case_id):
    model = workspace(case_id)
    return jsonify(html=render_template("_evidence_workspace.html", workspace=model),
                   active=model["active"])


@evidence.get("/api/case/<case_id>/workspace/run/<run_id>")
def workspace_run(case_id, run_id):
    """Read bounded, published reports for this evidence and its descendants only."""
    model = workspace(case_id)
    run = runtime_repository().run(run_id)
    paths = {normalize(item["path"]) for item in model["derived"]}
    if model["selected"]:
        paths.add(normalize(model["selected"]["path"]))
    if not run or run["case_id"] != case_id or normalize(run["source_path"]) not in paths:
        raise ValidationError("Run does not belong to this evidence workspace.")
    files = [item for item in runtime_repository().artifacts(run_id) if item.get("complete")]
    material_paths = {normalize(item["path"]) for item in model["derived"]}
    reports = [item for item in files if item["name"].lower().endswith((".txt", ".csv", ".json", ".jsonl"))
               and not item["name"].startswith("_sifted/") and normalize(item["path"]) not in material_paths]
    captured = [item for item in model["derived"] if item["source_run_id"] == run_id]
    name = request.args.get("report", reports[0]["name"] if reports else "")
    report = next((item for item in reports if item["name"] == name), None)
    content, truncated = "", False
    if name and not report:
        raise ValidationError("Choose a published report from this run.")
    if report:
        if not allowed(report["path"], runtime_settings().output_roots):
            raise ValidationError("This published report is outside the configured result roots.")
        try:
            descriptor = os.open(report["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise ValidationError("This published report is no longer a regular file.")
                data = handle.read(128 * 1024 + 1)
            truncated = len(data) > 128 * 1024
            content = data[:128 * 1024].decode("utf-8", errors="replace")
        except OSError:
            raise ValidationError("This published report is no longer available.")
    return jsonify(html=render_template("_evidence_result.html", run=run, reports=reports[:100],
                                       report=name, content=content, truncated=truncated, captured=captured,
                                       workspace=model),
                   **recipe(Plan.from_dict(run["plan"]), runtime_settings()))


@evidence.post("/case/<case_id>/evidence/<artifact_id>/type")
def set_evidence_type(case_id, artifact_id):
    case = case_or_error(case_id)
    item = select_input(case, runtime_repository(), "e:" + artifact_id)
    chosen = request.form.get("type", "")
    if chosen not in ARTIFACT_TYPES:
        raise ValidationError("Choose a supported evidence type.")

    def update(current):
        selected = next((x for x in current["artifacts"] if x["id"] == item["id"]), None)
        if not selected:
            raise StoreError("Evidence is no longer registered.")
        selected.update(type=chosen, type_basis="analyst")

    runtime_repository().mutate_case(case_id, update)
    return redirect(url_for("evidence.case_workspace", case_id=case_id, input="e:" + artifact_id))
