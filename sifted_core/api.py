"""HTTP endpoints for validated plans and the durable queue."""
import json
import time
import uuid

from flask import Blueprint, jsonify, request, stream_with_context

from .adapters import ValidationError, compile_plan
from .storage import StoreError, utc_now

TERMINAL = {"success", "error", "cancelled", "interrupted"}


def create_blueprint(repository_factory, settings_factory):
    api = Blueprint("execution", __name__)

    def payload():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ValidationError("Request must be a JSON object.")
        return value

    def run_or_404(run_id):
        run = repository_factory().run(run_id)
        if not run:
            raise StoreError("Run not found.")
        return run

    @api.errorhandler(ValidationError)
    @api.errorhandler(StoreError)
    def validation_error(exc):
        return jsonify(error=str(exc)), 404 if str(exc) == "Run not found." else 400

    def response_plan(plan):
        commands = plan.commands()
        return {"command": "\n".join(commands), "commands": commands, "output_path": plan.output_path,
                "preview_note": "Tool output is staged in <staging_output>; <job_workspace> holds generated configuration. "
                                "The actual commands and configuration are saved with the run.",
                "operation": plan.operation, "parameters": plan.parameters}

    @api.post("/api/<tool_id>/preview")
    def preview(tool_id):
        plan, _, _ = compile_plan(tool_id, payload(), settings_factory(), repository_factory(), preview=True)
        return jsonify(response_plan(plan))

    def enqueue(tool_id, data):
        repo = repository_factory()
        plan, case_id, input_record = compile_plan(tool_id, data, settings_factory(), repo)
        run_id = uuid.uuid4().hex
        run = {"id": run_id, "tool": plan.tool, "adapter_id": tool_id, "case_id": case_id,
               "source_path": plan.source, "output_path": plan.output_path, "log_path": plan.output_path + ".log",
               "status": "queued", "created_at": utc_now(), "command": "\n".join(plan.commands()),
               "parameters": data, "plan": plan.to_dict()}
        repo.enqueue(run, input_record)
        return {**response_plan(plan), "status": "queued", "run_id": run_id}

    @api.post("/api/<tool_id>/run")
    def start(tool_id):
        return jsonify(enqueue(tool_id, payload())), 202

    @api.post("/api/run/<run_id>/cancel")
    def cancel(run_id):
        run = repository_factory().request_cancel(run_id)
        message = "Finalizing results; cancellation is no longer available." if run.get("finalizing") else "Cancellation requested."
        return jsonify(status=run["status"], message=message)

    @api.post("/api/run/<run_id>/retry")
    def retry(run_id):
        run = run_or_404(run_id)
        if run["status"] not in TERMINAL or not run.get("adapter_id"):
            raise ValidationError("Only completed durable runs can be retried.")
        data = {**run["parameters"], "output_path": run["output_path"] + "-retry-" + uuid.uuid4().hex[:8]}
        return jsonify(enqueue(run["adapter_id"], data)), 202

    @api.get("/api/run/<run_id>/status")
    def status(run_id):
        run = run_or_404(run_id)
        return jsonify({key: run.get(key) for key in ("id", "tool", "status", "created_at", "output_path",
                                                     "exit_code", "error", "current_step", "completed_at", "string_count", "file_count", "mismatch_count")})

    @api.get("/api/run/<run_id>/events")
    def events(run_id):
        run_or_404(run_id)
        try:
            cursor = max(0, int(request.headers.get("Last-Event-ID") or request.args.get("after", "0")))
        except ValueError:
            raise ValidationError("Invalid event cursor.")
        repo = repository_factory()

        @stream_with_context
        def stream():
            after = cursor
            while True:
                batch = repo.events(run_id, after)
                for event in batch:
                    after = event["id"]
                    data = {"type": event["type"], "message": event["message"]}
                    if event["type"] == "done":
                        run = repo.run(run_id)
                        data.update(status=run["status"], error=run.get("error"))
                        data.update({key: run.get(key) for key in ("string_count", "file_count", "mismatch_count")})
                    yield f"id: {after}\nevent: {event['type']}\ndata: {json.dumps(data)}\n\n"
                    if event["type"] == "done":
                        return
                run = repo.run(run_id)
                if not batch and run["status"] in TERMINAL:
                    yield "event: done\ndata: " + json.dumps({"type": "done", "message": str(run.get("exit_code") or 0),
                                                               "status": run["status"], "error": run.get("error")}) + "\n\n"
                    return
                if not batch:
                    yield ": keepalive\n\n"
                    time.sleep(0.5)

        from flask import Response
        return Response(stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @api.get("/api/health")
    def health():
        return jsonify(status="ok", worker=repository_factory().worker_status())

    @api.get("/api/runs")
    def runs():
        repo = repository_factory()
        cases = {c["id"]: c for c in repo.cases()}
        wanted = request.args.get("status")
        statuses = ["queued", "running"] if wanted == "active" else ([wanted] if wanted else None)
        if statuses and any(status not in TERMINAL | {"queued", "running"} for status in statuses):
            raise ValidationError("Unknown run status.")
        values = []
        for run in repo.runs(statuses=statuses):
            values.append({**{k: run.get(k) for k in ("id", "tool", "status", "created_at", "command", "source_path", "output_path",
                                                       "error", "exit_code", "adapter_id", "completed_at")},
                           "case_name": cases.get(run.get("case_id"), {}).get("name")})
        return jsonify(runs=values)

    return api
