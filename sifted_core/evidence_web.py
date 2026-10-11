"""An optional evidence-first interface over the existing forensic workflows."""
from pathlib import Path

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from .context import runtime_repository, runtime_settings
from .evidence_workspace import identify, partition_choices, resolve_actions, select_input, validate_context, workspace_inputs
from .presentation import ARTIFACT_TYPES
from .storage import StoreError
from .tool_base import ValidationError, allowed, executable, normalize
from .file_triage import browse


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


def disk_journey(selected, observed, runs, partitions, case_id, key):
    """Project preparation from successful runs; never store parallel workflow state."""
    successful = [run for run in runs if run["status"] == "success" and selected.get("hash") == run.get("input_sha256")]
    geometries = {(p["offset_sector"], p["sector_size"]): dict(p) for p in partitions}
    for run in successful:
        if run["tool"] in {"fsstat", "fls"}:
            params = run["plan"]["parameters"]
            geometry = (params.get("offset_sector", 0), params.get("sector_size"))
            geometries.setdefault(geometry, {"offset_sector": geometry[0], "sector_size": geometry[1], "description": "Examined filesystem"})
    if observed["kind"] == "filesystem" and not geometries:
        geometries[(0, None)] = {"offset_sector": 0, "sector_size": None, "description": "Filesystem image"}
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
        params = {"case_id": case_id, "source_path": selected["path"], "workspace_input": key,
                  "offset_sector": geometry[0], "sector_size": geometry[1], "workspace_tab": "analysis"}
        if context:
            params.update(context_run_id=context["id"], workspace_context=context["id"])
        elif card.get("actions"):
            # Preserve the verified partition-map context on preparation actions.
            card["stat_url"] = card["actions"][0]["url"]
            card["inventory_url"] = card["actions"][1]["url"]
        card.setdefault("stat_url", url_for("web.additional_workflow", tool_id="fsstat", **params))
        card.setdefault("inventory_url", url_for("web.additional_workflow", tool_id="fls", recursive="true", **params))
        card.update(stat_run_id=stat["id"] if stat else None, inventory_run_id=inventory["id"] if inventory else None,
                    stat_reason=tool_reason("fsstat"), inventory_reason=tool_reason("fls"),
                    entry_count=inventory["analysis"]["entry_count"] if inventory else 0,
                    triage_url=url_for("evidence.case_workspace", case_id=case_id, input=key, tab="triage", context_run_id=inventory["id"]) if inventory else None,
                    stat_result_url=url_for("web.workflow_analysis", run_id=stat["id"], case_id=case_id, workspace_input=key) if stat else None,
                    blocks=[{"label": label, "url": url_for("web.additional_workflow", tool_id=tool, **params), "reason": tool_reason(tool)}
                            for tool, label in (("blkstat", "Check block allocation"), ("blkcat", "Read a block"), ("blkls", "Sample unallocated blocks"), ("blkcalc", "Map a block address"))] if context else [])
        cards.append(card)
    return cards


def triage_view(context, selected, case_id, key):
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
    common = {"case_id": case_id, "input": key, "tab": "triage", "context_run_id": context["id"]}
    result.update(metadata_reason=tool_reason("istat"), extract_reason=tool_reason("icat"))
    filters = {"directory": directory, "q": result["query"], "kind": result["kind"], "state": result["state"], "scope": result["scope"]}
    result["root_url"] = url_for("evidence.case_workspace", **common)
    for crumb in result["breadcrumbs"]:
        crumb["url"] = url_for("evidence.case_workspace", directory=crumb["id"], **common)
    result["previous_url"] = url_for("evidence.case_workspace", offset=max(0, result["offset"] - 100), **common, **filters) if result["offset"] else None
    result["next_url"] = url_for("evidence.case_workspace", offset=result["offset"] + 100, **common, **filters) if result["offset"] + len(result["rows"]) < result["total"] else None
    geometry = {name: context["plan"]["parameters"][name] for name in ("offset_sector", "sector_size") if name in context["plan"]["parameters"]}
    for row in result["rows"]:
        params = {"case_id": case_id, "source_path": selected["path"], "workspace_input": key,
                  "context_run_id": context["id"], "workspace_context": context["id"], "entry_id": row["id"],
                  "workspace_tab": "triage", "workspace_directory": directory, "workspace_query": result["query"],
                  "workspace_kind": result["kind"], "workspace_state": result["state"], "workspace_scope": result["scope"],
                  "workspace_offset": result["offset"], **geometry}
        row["metadata_url"] = url_for("web.additional_workflow", tool_id="istat", metadata_address=row["address"], **params)
        if row["kind"] == "directory" and row["parent"] is not None:
            row["directory_url"] = url_for("evidence.case_workspace", directory=row["id"], **common) if result["recursive"] and not row["ambiguous_path"] else url_for("web.additional_workflow", tool_id="fls", directory_inode=row["address"], recursive="true", **params)
        if row["kind"] == "file" and row["name"] not in {"", ".", "..", "_sifted"} and "\\" not in row["name"]:
            row["extract_url"] = url_for("web.additional_workflow", tool_id="icat", metadata_address=row["address"], entry_name=row["name"], recover_deleted="true" if row["deleted"] else "false", **params)
    return result


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
    for run in selected_runs[:50]:
        run["result_files"] = [item for item in repo.artifacts(run["id"])
                               if allowed(item["path"], settings.output_roots) and Path(item["path"]).is_file()][:12]
        run["result_url"] = url_for("web.workflow_analysis", run_id=run["id"], case_id=case_id,
                                    workspace_input=key) if run.get("analysis") else None
    actions = resolve_actions(selected, observed, settings, runs, context) if selected else []
    for action in actions:
        endpoint = {"strings": "web.strings_tool", "artifact-triage": "web.artifact_timeline",
                    "bulk-extractor": "web.bulk_extractor", "eric-zimmerman": "web.eric_zimmerman"}.get(action["tool"])
        if not endpoint:
            endpoint = "web.additional_workflow" if action["tool"] in {"mmls", "fsstat", "fls", "xxd", "head", "pdfinfo", "pdftotext"} else "web." + action["tool"]
        parameters = dict(action["parameters"])
        if endpoint == "web.additional_workflow":
            parameters["tool_id"] = action["tool"]
        action["url"] = url_for(endpoint, case_id=case_id, source_path=selected["path"],
                                workspace_input=key, workspace_context=context_id or None, **parameters)
        if action["result_run_id"]:
            result = repo.run(action["result_run_id"])
            action["result_url"] = url_for("web.workflow_analysis", run_id=result["id"], case_id=case_id, workspace_input=key)
    maps = [r for r in selected_runs if r["tool"] == "mmls" and r["status"] == "success"
            and selected.get("hash") == r.get("input_sha256")]
    partitions = partition_choices(maps[0], repo, settings) if maps else []
    for partition in partitions:
        partition["actions"] = [{"label": label, "url": url_for(
            "web.additional_workflow", tool_id=tool, case_id=case_id, source_path=selected["path"],
            workspace_input=key, context_run_id=maps[0]["id"], offset_sector=partition["offset_sector"],
            sector_size=partition["sector_size"], recursive="true" if tool == "fls" else None,
            workspace_tab="analysis")} for tool, label in (("fsstat", "Describe filesystem"), ("fls", "Build file inventory"))]
    is_disk = bool(observed and observed["kind"] in {"disk", "filesystem", "ewf", "container"})
    tab = request.args.get("tab", "analysis" if is_disk else "tools")
    if tab not in {"analysis", "triage", "derived", "tools"}:
        raise ValidationError("Choose an available workspace tab.")
    if not is_disk and selected and tab in {"analysis", "triage"}:
        raise ValidationError("Disk analysis and filesystem triage require disk or filesystem evidence.")
    journey = disk_journey(selected, observed, selected_runs, partitions, case_id, key) if is_disk else []
    if tab == "triage" and not context:
        inventories = [card for card in journey if card["inventory_run_id"]]
        if len(inventories) == 1:
            context = validate_context(repo.run(inventories[0]["inventory_run_id"]), selected, case_id)
    triage = triage_view(context, selected, case_id, key) if tab == "triage" and selected else None
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
    for item in derived:
        item["url"] = url_for("evidence.case_workspace", case_id=case_id, input=item["key"], tab="tools")
    input_offset = max(0, request.args.get("input_offset", 0, type=int))
    return {"case": case, "inputs": inputs[input_offset:input_offset + 100], "input_offset": input_offset,
            "input_count": len(inputs), "selected": selected, "observed": observed, "actions": actions,
            "runs": selected_runs[:50], "run_count": len(selected_runs), "parent_input": parent_input,
            "context": context, "types": ARTIFACT_TYPES, "partitions": partitions,
            "is_disk": is_disk, "tab": tab, "journey": journey, "triage": triage, "derived": derived,
            "completed_count": sum(r["status"] == "success" for r in selected_runs),
            "active_count": sum(r["status"] in {"running", "queued"} for r in selected_runs)}


@evidence.get("/case/<case_id>/workspace")
def case_workspace(case_id):
    return render_template("evidence_workspace.html", cases=runtime_repository().cases(), workspace=workspace(case_id))


@evidence.get("/api/case/<case_id>/workspace")
def workspace_api(case_id):
    return jsonify(workspace(case_id))


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
