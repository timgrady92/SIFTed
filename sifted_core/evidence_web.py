"""An optional evidence-first interface over the existing forensic workflows."""
from pathlib import Path

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from .context import runtime_repository, runtime_settings
from .evidence_workspace import identify, partition_choices, resolve_actions, select_input, validate_context, workspace_inputs
from .presentation import ARTIFACT_TYPES
from .storage import StoreError
from .tool_base import ValidationError, allowed, normalize


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


def workspace(case_id):
    repo, settings = runtime_repository(), runtime_settings()
    case = case_or_error(case_id)
    inputs = workspace_inputs(case, repo)
    key = request.args.get("input", inputs[0]["key"] if inputs else "")
    selected = select_input(case, repo, key) if key else None
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
    contexts = [r for r in selected_runs if r["status"] == "success" and r["tool"] in {"fsstat", "fls"}
                and selected.get("hash") == r.get("input_sha256")]
    # One card per filesystem geometry, retaining the latest successful context.
    filesystems = {}
    for run in contexts:
        parameters = run["plan"]["parameters"]
        geometry = (parameters.get("offset_sector", 0), parameters.get("sector_size"))
        filesystems.setdefault(geometry, {"offset_sector": geometry[0], "sector_size": geometry[1], "run_id": run["id"],
                                         "url": url_for("evidence.case_workspace", case_id=case_id, input=key, context_run_id=run["id"])})
    maps = [r for r in selected_runs if r["tool"] == "mmls" and r["status"] == "success"
            and selected.get("hash") == r.get("input_sha256")]
    partitions = partition_choices(maps[0], repo, settings) if maps else []
    for partition in partitions:
        partition["actions"] = [{"label": label, "url": url_for(
            "web.additional_workflow", tool_id=tool, case_id=case_id, source_path=selected["path"],
            workspace_input=key, context_run_id=maps[0]["id"], offset_sector=partition["offset_sector"],
            sector_size=partition["sector_size"])} for tool, label in (("fsstat", "Describe filesystem"), ("fls", "Browse files"))]
    input_offset = max(0, request.args.get("input_offset", 0, type=int))
    return {"case": case, "inputs": inputs[input_offset:input_offset + 100], "input_offset": input_offset,
            "input_count": len(inputs), "selected": selected, "observed": observed, "actions": actions,
            "runs": selected_runs[:50], "run_count": len(selected_runs), "filesystems": list(filesystems.values()),
            "context": context, "types": ARTIFACT_TYPES, "partitions": partitions,
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
