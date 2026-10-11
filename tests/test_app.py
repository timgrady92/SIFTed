"""HTTP workflows against isolated application instances."""
import pytest
import app as sifted_app
from sifted_core.worker import Worker


@pytest.fixture
def application(tmp_path):
    app = sifted_app.create_app({"TESTING": True, "SIFTED_DATABASE_PATH": str(tmp_path / "sifted.db"),
                               "SIFTED_INPUT_ROOTS": [str(tmp_path)], "SIFTED_OUTPUT_ROOTS": [str(tmp_path)]})
    with app.app_context():
        yield app.test_client(), tmp_path


def test_exiftool_rejects_unknown_format(application):
    client, root = application
    source = root / "source"
    source.write_bytes(b"test")
    response = client.post("/api/exiftool/run", json={"source_path": str(source), "output_path": str(root / "out"), "output_format": "weird"})
    assert response.status_code == 400
    assert sifted_app.runtime_repository().runs() == []


def test_terminal_preview_is_read_only_and_matches_submitted_recipe(application):
    client, root = application
    source = root / "source with spaces"
    source.write_bytes(b"test")
    data = {"source_path": str(source), "output_path": str(root / "out"), "mode": "mime", "recursive": True}
    preview = client.post("/api/filetype/preview", json=data)
    run = client.post("/api/filetype/run", json=data)
    assert preview.status_code == 200 and run.status_code == 202
    assert preview.json["terminal_command"] == run.json["terminal_command"]
    queued = sifted_app.runtime_repository().run(run.json["run_id"])
    assert queued["plan"]["steps"][0]["argv"][1:3] == ["--mime-type", "-b"]
    assert preview.json["terminal_ready"] and preview.json["terminal_command"].startswith("file --mime-type")
    assert "<staging_output>" not in preview.json["terminal_command"]
    assert "<job_workspace>" not in preview.json["terminal_command"]
    assert not (root / "out").exists()
    assert client.get(f"/api/run/{run.json['run_id']}/status").json["status"] == "queued"


def test_terminal_snippet_requires_real_evidence(application):
    client, _ = application
    response = client.post("/api/strings/preview", json={})
    assert response.status_code == 200
    assert not response.json["terminal_ready"]
    assert "Select an existing evidence path" in response.json["terminal_command"]
    assert sifted_app.runtime_repository().runs() == []


def test_malformed_requests_do_not_create_jobs(application):
    client, _ = application
    for payload in ([1], None, {"source_path": 1}, {"output_path": []}):
        assert client.post("/api/strings/run", json=payload).status_code == 400
    assert sifted_app.runtime_repository().runs() == []


def test_input_root_enforcement_in_case_creation(application, monkeypatch):
    client, root = application
    allowed = root / "allowed"
    allowed.mkdir()
    sifted_app.runtime_settings().input_roots = [str(allowed)]
    assert client.post("/cases", data={"name": "test", "source_path": str(root / "outside")}).status_code == 403


def test_workflow_and_case_pages_render(application):
    client, root = application
    response = client.post("/cases", data={"name": "Review case"})
    assert response.status_code == 302
    case_id = sifted_app.runtime_repository().cases()[0]["id"]
    for path in ("/", "/cases", "/tools", "/strings", "/foremost", "/scalpel", "/bulk-extractor", "/volatility", "/artifact-timeline", "/eric-zimmerman", "/exiftool", "/filetype", "/guides", "/glossary", f"/case/{case_id}/results"):
        assert client.get(path).status_code == 200, path


def test_durable_events_replay_for_independent_viewers(application):
    client, root = application
    source = root / "source"
    source.write_bytes(b"meaningful strings sample\x00")
    created = client.post("/api/strings/run", json={"source_path": str(source), "output_path": str(root / "out")}).json
    Worker(sifted_app.runtime_repository(), sifted_app.runtime_settings()).run_once()
    url = f"/api/run/{created['run_id']}/events"
    first = client.get(url).data
    assert first == client.get(url).data and b"event: done" in first
    last_event = sifted_app.runtime_repository().events(created["run_id"])[-1]["id"]
    replay = client.get(url, headers={"Last-Event-ID": str(last_event - 1)}).data
    assert b"event: done" in replay and b"Queued for execution" not in replay
    assert client.get(f"/api/run/{created['run_id']}/results").json["files"]


def test_cancellation_and_retry_preserve_original_run(application):
    client, root = application
    source = root / "source"
    source.write_bytes(b"retry this sample\x00")
    created = client.post("/api/strings/run", json={"source_path": str(source), "output_path": str(root / "out")}).json
    run_id = created["run_id"]
    assert client.post(f"/api/run/{run_id}/cancel").json["status"] == "cancelled"
    retried = client.post(f"/api/run/{run_id}/retry")
    assert retried.status_code == 202 and retried.json["output_path"] != created["output_path"]
    assert len(sifted_app.runtime_repository().runs()) == 2
    assert client.post("/api/run/missing/cancel").status_code == 404


def test_artifacts_are_the_case_evidence_source(application):
    client, root = application
    source = root / "evidence.txt"
    source.write_text("registered evidence")
    assert client.post("/cases", data={"name": "Case", "source_path": str(source)}).status_code == 302
    case = sifted_app.runtime_repository().cases()[0]
    assert "source_path" not in case and "file_hash" not in case
    artifact = case["artifacts"][0]
    assert artifact["hash"]
    assert client.delete(f"/api/case/{case['id']}/artifacts/{artifact['id']}").status_code == 200
    assert client.get(f"/api/case/{case['id']}").json["case"]["artifacts"] == []
    for payload in ([1], {"path": 1}, {"path": str(source), "type": "invalid"}):
        assert client.post(f"/api/case/{case['id']}/artifacts", json=payload).status_code == 400


def test_disallowed_text_is_never_opened_for_format_detection(application, monkeypatch):
    client, root = application
    outside = root.parent / "outside.txt"
    outside.write_text("sensitive text")
    monkeypatch.setattr("sifted_core.web.detect_text_table_format", lambda *_: pytest.fail("Read disallowed file"))
    assert client.get("/api/table-rows", query_string={"path": str(outside)}).status_code == 400
    response = client.get("/view-file", query_string={"path": str(outside)})
    assert b"Access denied" in response.data


def test_log_reads_are_bounded_and_running_logs_are_visible(application):
    client, root = application
    source = root / "source"
    source.write_bytes(b"test")
    created = client.post("/api/strings/run", json={"source_path": str(source), "output_path": str(root / "out")}).json
    repo = sifted_app.runtime_repository()
    run = repo.claim()
    worker = Worker(repo, sifted_app.runtime_settings())
    workspace = worker.workspace(run)
    workspace.mkdir(parents=True)
    (workspace / "run.log").write_text("prefix\n" + "line\n" * 300000 + "last\n")
    response = client.get(f"/api/run/{created['run_id']}/log")
    assert response.json["truncated"] and len(response.json["log"].encode()) <= 1024 * 1024
    tail = client.get(f"/api/run/{created['run_id']}/tail", query_string={"lines": 2})
    assert tail.json["lines"] == ["line\n", "last\n"]
