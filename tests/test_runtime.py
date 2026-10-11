import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.tool_base import Plan, Settings, Step, ValidationError
from sifted_core.storage import Repository, StoreError, utc_now
from sifted_core.tables import ResultTables
from sifted_core.worker import Worker, process_identity


@pytest.fixture
def runtime(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    source = evidence / 'source with spaces and "quotes".bin'
    source.write_bytes(b"forensic test sample\x00")
    script = tmp_path / "fake tools.py"
    script.write_text('''import json,sys
from pathlib import Path
tool,*args=sys.argv[1:]
def option(name): return args[args.index(name)+1]
if tool=="bulk-extractor":
 p=Path(option("-o")); p.mkdir(parents=True); (p/"audit.txt").write_text("preserved raw output")
elif tool=="log2timeline":
 p=Path(option("--storage_file")); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b"storage")
elif tool=="psort": Path(option("-w")).write_text("Time,Value\\n2026-01-01,1\\n")
elif tool=="exiftool": print("SourceFile,FileType\\nexample,TXT")
elif tool=="filetype": print("image/png")
else: print("0 forensic strings")
''')
    binaries = {tool: [sys.executable, str(script), tool] for tool in
                ["bulk-extractor", "log2timeline", "psort", "exiftool", "strings", "filetype"]}
    settings = Settings(input_roots=[str(evidence)], output_roots=[str(outputs)],
                        binaries=binaries, timeout_seconds=5)
    return Repository(tmp_path / "runtime.db"), settings, source, outputs


def enqueue(repo, plan, input_record, case_id=None):
    run = {"id": uuid.uuid4().hex, "tool": plan.tool, "status": "queued", "case_id": case_id,
           "created_at": utc_now(), "output_path": plan.output_path, "log_path": plan.output_path + ".log", "plan": plan.to_dict()}
    repo.enqueue(run, input_record)
    return run


def compiled(runtime, tool="strings", **options):
    repo, settings, source, outputs = runtime
    payload = {"source_path": str(source), "output_path": str(outputs / uuid.uuid4().hex), **options}
    plan, case, input_record = compile_plan(tool, payload, settings, repo)
    return enqueue(repo, plan, input_record, case)


@pytest.mark.parametrize("tool,options", [
    ("strings", {}), ("exiftool", {}),
    ("bulk-extractor", {"focus_scanners": ["email"]}),
    ("artifact-triage", {}), ("filetype", {}),
])
def test_command_and_builtin_operations_use_shared_worker(runtime, tool, options):
    repo, settings, source, outputs = runtime
    options = dict(options)
    run = compiled(runtime, tool, **options)
    Worker(repo, settings).run_once()
    completed = repo.run(run["id"])
    assert completed["status"] == "success", completed.get("error")
    files = repo.artifacts(run["id"])
    assert files
    for entry in files:
        assert entry["sha256"] == hashlib.sha256(Path(entry["path"]).read_bytes()).hexdigest()
    assert Path(run["output_path"], "_sifted/provenance.json").exists()
    assert repo.events(run["id"])[-1]["type"] == "done"


@pytest.mark.parametrize("tool,options", [
    ("strings", {"encodng": "l"}), ("strings", {"encoding": "--help"}), ("strings", {"min_length": True}), ("strings", {"min_length": 0}),
    ("strings", {"show_offsets": "false"}), ("exiftool", {"output_format": "xml"}),
    ("artifact-triage", {"timezone": "not-a-time-zone"}), ("bulk-extractor", {"focus_scanners": ["unknown"]}),
    ("filetype", {"mode": "invalid"}), ("filetype", {"mode": "full", "mismatch_only": True}),
])
def test_invalid_options_fail_before_enqueue(runtime, tool, options):
    with pytest.raises(ValidationError):
        compiled(runtime, tool, **options)
    assert runtime[0].runs() == []


def test_atomic_claims_and_output_reservations(runtime):
    repo = runtime[0]
    run = compiled(runtime)
    with pytest.raises(StoreError):
        enqueue(repo, Plan.from_dict(run["plan"]), repo.input(run["id"]))
    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = list(pool.map(lambda _: repo.claim(), range(2)))
    assert sum(value is not None for value in claimed) == 1


def test_concurrent_case_updates_do_not_lose_artifacts(runtime):
    repo = runtime[0]
    repo.add_case({"id": "case", "artifacts": []})
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: repo.mutate_case("case", lambda case: case["artifacts"].append({"id": str(i)})), range(20)))
    assert len(repo.case("case")["artifacts"]) == 20


def test_schema_refuses_unknown_versions_without_mutation(tmp_path):
    import sqlite3
    path = tmp_path / "db"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(StoreError, match="newer"):
        Repository(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99
        assert not db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()


def test_source_change_while_queued_is_visible_failure(runtime):
    repo, settings, source, _ = runtime
    run = compiled(runtime)
    source.write_bytes(b"different input")
    Worker(repo, settings).run_once()
    assert repo.run(run["id"])["status"] == "error"
    assert "changed while queued" in repo.run(run["id"])["error"]


def test_baseline_mismatch_prevents_tool_execution(runtime):
    repo, settings, source, outputs = runtime
    repo.add_case({"id": "case", "slug": "case", "artifacts": [{"id": "evidence", "path": str(source), "hash": "0" * 64}]})
    run = compiled(runtime, case_id="case")
    Worker(repo, settings).run_once()
    assert "baseline" in repo.run(run["id"])["error"]
    assert repo.run(run["id"])["steps"] == []


def custom_run(runtime, program, **step_options):
    repo, settings, source, outputs = runtime
    plan, _, record = compile_plan("strings", {"source_path": str(source), "output_path": str(outputs / uuid.uuid4().hex)}, settings, repo)
    plan.steps = [Step([sys.executable, "-c", program], "Test subprocess", "{output}/result.txt", **step_options)]
    plan.expected_files = ["result.txt"]
    return enqueue(repo, plan, record)


def test_timeout_preserves_partial_output_and_nonzero_status(runtime):
    repo, settings, _, _ = runtime
    run = custom_run(runtime, "import time; print('partial',flush=True); time.sleep(20)", timeout=1)
    Worker(repo, settings).run_once()
    completed = repo.run(run["id"])
    assert completed["status"] == "error" and completed["steps"][0]["return_code"] == 124
    assert Path(run["output_path"], "result.txt").read_text() == "partial\n"
    assert all(not item["complete"] for item in repo.artifacts(run["id"]))


def test_output_limit_terminates_noisy_tool(runtime):
    repo, settings, _, _ = runtime
    settings.max_output_bytes = 1024
    run = custom_run(runtime, "import sys; sys.stdout.write('x'*1000000)")
    Worker(repo, settings).run_once()
    assert repo.run(run["id"])["status"] == "error" and "budget" in repo.run(run["id"])["error"]


def test_running_cancellation_terminates_process_group(runtime):
    repo, settings, _, _ = runtime
    run = custom_run(runtime, "import subprocess,time; print('partial',flush=True); subprocess.Popen(['sleep','20']); time.sleep(20)")
    worker = Worker(repo, settings)
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    deadline = time.monotonic() + 5
    while not repo.run(run["id"]).get("process") and time.monotonic() < deadline:
        time.sleep(0.02)
    active = repo.run(run["id"]).get("process")
    assert active
    repo.request_cancel(run["id"])
    thread.join(timeout=5)
    assert not thread.is_alive() and repo.run(run["id"])["status"] == "cancelled"
    assert process_identity(active["pid"]) is None


def test_recovery_after_publication_before_commit(runtime, monkeypatch):
    repo, settings, _, _ = runtime
    run = compiled(runtime)
    worker = Worker(repo, settings)
    original = repo.finish
    monkeypatch.setattr(repo, "finish", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        worker.run_once()
    monkeypatch.setattr(repo, "finish", original)
    assert repo.run(run["id"])["status"] == "running" and Path(run["output_path"]).is_dir()
    worker.recover()
    assert repo.run(run["id"])["status"] == "interrupted" and repo.artifacts(run["id"])


def test_recovery_preserves_staging_and_kills_orphan(runtime):
    repo, settings, _, _ = runtime
    run = compiled(runtime)
    repo.claim()
    worker = Worker(repo, settings)
    workspace = worker.workspace(run)
    (workspace / "output").mkdir(parents=True)
    (workspace / "output/partial.txt").write_text("partial evidence")
    orphan = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], start_new_session=True)
    try:
        repo.update(run["id"], {"process": {"pid": orphan.pid, "start_time": process_identity(orphan.pid)}})
        worker.recover()
        orphan.wait(timeout=5)
        assert repo.run(run["id"])["status"] == "interrupted"
        assert Path(run["output_path"], "partial.txt").read_text() == "partial evidence"
    finally:
        if orphan.poll() is None:
            os.killpg(orphan.pid, signal.SIGKILL)
            orphan.wait()


def test_csv_cache_pages_and_invalidates(tmp_path):
    source = tmp_path / "rows.csv"
    source.write_text("Name,Value\n" + "".join(f"row{i},{i}\n" for i in range(2000)))
    cache = ResultTables(tmp_path / "cache.db")
    data, total, more = cache.page(source, 1200, 10)
    assert total == 2000 and more and data["rows"][0] == ["row1200", "1200"]
    source.write_text("Name,Value\nreplacement,3\n")
    data, total, more = cache.page(source)
    assert total == 1 and not more and data["rows"] == [["replacement", "3"]]


def test_directory_member_change_is_detected_before_execution(runtime):
    repo, settings, source, _ = runtime
    nested = source.parent / "nested"
    nested.mkdir()
    member = nested / "member.txt"
    member.write_text("original")
    run = compiled(runtime, "filetype", source_path=str(source.parent))
    member.write_text("changed below unchanged directory root")
    Worker(repo, settings).run_once()
    assert repo.run(run["id"])["status"] == "error"
    assert "changed while queued" in repo.run(run["id"])["error"]
    assert not repo.run(run["id"]).get("process")


def test_directory_symlinks_are_rejected(runtime):
    source = runtime[2]
    (source.parent / "linked-evidence").symlink_to(source)
    with pytest.raises(ValidationError, match="symbolic links"):
        compiled(runtime, "filetype", source_path=str(source.parent))


def test_zero_exit_without_expected_file_is_a_failure(runtime):
    repo, settings, _, _ = runtime
    settings.binaries["log2timeline"] = [sys.executable, "-c", "pass"]
    run = compiled(runtime, "artifact-triage")
    Worker(repo, settings).run_once()
    result = repo.run(run["id"])
    assert result["status"] == "error"
    assert "expected output" in result["error"]
    assert Path(run["output_path"], "_sifted/provenance.json").is_file()


def test_cancellation_remains_active_after_child_closes_pipes(runtime):
    repo, settings, _, _ = runtime
    settings.binaries["strings"] = [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"]
    run = compiled(runtime)
    worker = Worker(repo, settings)
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    deadline = time.monotonic() + 5
    while not repo.run(run["id"]).get("process") and time.monotonic() < deadline:
        time.sleep(0.02)
    repo.request_cancel(run["id"])
    thread.join(timeout=5)
    assert not thread.is_alive()
    result = repo.run(run["id"])
    assert result["status"] == "cancelled"
    assert result["steps"][0]["return_code"] == 130
    assert result["steps"][0]["error"]


def test_terminal_results_and_output_reservations_are_immutable(runtime):
    repo, settings, _, _ = runtime
    run = compiled(runtime)
    Worker(repo, settings).run_once()
    with pytest.raises(StoreError):
        repo.update(run["id"], {"status": "queued"})
    with pytest.raises(StoreError):
        repo.finish(run["id"], {"status": "error", "exit_code": 1})
    with pytest.raises(StoreError):
        enqueue(repo, Plan.from_dict(run["plan"]), repo.input(run["id"]))


def test_independent_worker_process_consumes_queue_and_excludes_second_worker(runtime):
    repo, settings, _, _ = runtime
    run = compiled(runtime)
    environment = {**os.environ, "SIFTED_DATABASE_PATH": str(repo.path),
                   "SIFTED_INPUT_ROOTS": ",".join(settings.input_roots),
                   "SIFTED_OUTPUT_ROOTS": ",".join(settings.output_roots),
                   "SIFTED_BINARIES": json.dumps(settings.binaries)}
    process = subprocess.Popen([sys.executable, "-m", "sifted_core.worker"],
                               cwd=Path(__file__).resolve().parent.parent, env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while repo.run(run["id"])["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.05)
        assert repo.run(run["id"])["status"] == "success"
        assert repo.worker_status()["status"] == "online"
        second = subprocess.run([sys.executable, "-m", "sifted_core.worker"],
                                cwd=Path(__file__).resolve().parent.parent, env=environment,
                                capture_output=True, timeout=5)
        assert second.returncode != 0 and b"Another worker owns this database" in second.stderr
    finally:
        process.terminate()
        process.wait(timeout=10)
        process.stderr.close()
    assert repo.worker_status()["status"] == "offline"
    assert Repository(repo.path).artifacts(run["id"])


def test_staging_symlink_cannot_write_or_remove_outside_workspace(runtime, tmp_path):
    repo, settings, _, outputs = runtime
    run = compiled(runtime)
    outside = tmp_path / "outside"
    outside.mkdir()
    foreign_attempt = outside / run["id"]
    foreign_attempt.mkdir()
    marker = foreign_attempt / "unrelated.txt"
    marker.write_text("preserve this")
    (outputs / ".sifted-staging").symlink_to(outside, target_is_directory=True)
    Worker(repo, settings).run_once()
    assert repo.run(run["id"])["status"] == "error"
    assert marker.read_text() == "preserve this"
    assert list(foreign_attempt.iterdir()) == [marker]


def test_non_utf8_output_retains_attempt_and_worker_can_process_next_job(runtime):
    program = "import os; fd=os.open(b'output/invalid-name\\xff', os.O_WRONLY|os.O_CREAT, 0o600); os.write(fd,b'preserved bytes'); os.close(fd)"
    run = custom_run(runtime, program)
    worker = Worker(runtime[0], runtime[1])
    worker.run_once()
    result = runtime[0].run(run["id"])
    assert result["status"] == "error" and "non-UTF-8 path" in result["error"]
    retained = Path(result["retained_workspace"])
    assert retained.is_dir() and not Path(run["output_path"]).exists()
    invalid = os.fsencode(retained / "output") + b"/invalid-name\xff"
    with open(invalid, "rb") as handle:
        assert handle.read() == b"preserved bytes"
    assert runtime[0].artifacts(run["id"]) == []
    assert runtime[0].events(run["id"])[-1]["type"] == "done"
    following = compiled(runtime)
    worker.run_once()
    assert runtime[0].run(following["id"])["status"] == "success"


def test_private_inputs_can_change_without_altering_evidence_and_nested_configs_are_retained(runtime):
    from sifted_core.tool_base import OUTPUT, WORKSPACE
    repo, settings, source, outputs = runtime
    plan, case, record = compile_plan('strings', {'source_path':str(source), 'output_path':str(outputs/'captured')}, settings, repo)
    original = source.read_bytes()
    plan.input_copies = {str(source):'input/captured.bin'}
    plan.configs = {'maps/nested/query.map':'SELECT known;\n'}
    code = "from pathlib import Path; import sys; p=Path(sys.argv[1]); assert p.read_bytes()==bytes.fromhex(sys.argv[2]); p.write_bytes(b'changed private copy'); print('0 '+Path(sys.argv[3]).read_text().strip())"
    plan.steps = [Step([sys.executable,'-c',code,WORKSPACE+'/input/captured.bin',original.hex(),WORKSPACE+'/maps/nested/query.map'],'captured parser',OUTPUT+'/strings.txt')]
    run = enqueue(repo, plan, record, case)
    Worker(repo,settings).run_once()
    result = repo.run(run['id'])
    assert result['status']=='success',result.get('error')
    assert source.read_bytes()==original
    assert Path(result['output_path'],'_sifted/maps/nested/query.map').read_text()=='SELECT known;\n'
    assert not Path(result['output_path'],'_sifted/input').exists()


@pytest.mark.parametrize('action', ['metadata_symlink','config_changed','config_symlink','provenance_occupied'])
def test_tool_cannot_replace_managed_provenance_or_configuration(runtime, action, tmp_path):
    from sifted_core.tool_base import OUTPUT, WORKSPACE
    repo, settings, source, outputs = runtime
    external = tmp_path/'outside'; external.mkdir()
    marker=external/'marker';marker.write_text('untouched')
    actions = {
        'metadata_symlink': "(output/'_sifted').symlink_to(external,target_is_directory=True)",
        'config_changed': "config.write_text('changed')",
        'config_symlink': "config.unlink(); config.symlink_to(external/'marker')",
        'provenance_occupied': "(output/'_sifted').mkdir(); (output/'_sifted/provenance.json').write_text('spoofed')",
    }
    plan, case, record = compile_plan('strings',{'source_path':str(source),'output_path':str(outputs/action)},settings,repo)
    plan.configs={'maps/config.map':'original'}
    code="from pathlib import Path; import sys; output,config,external=map(Path,sys.argv[1:]); output.mkdir(exist_ok=True); "+actions[action]+"; print('0 output')"
    plan.steps=[Step([sys.executable,'-c',code,OUTPUT,WORKSPACE+'/maps/config.map',str(external)],'bad parser',OUTPUT+'/strings.txt')]
    run=enqueue(repo,plan,record,case);worker=Worker(repo,settings);worker.run_once()
    result=repo.run(run['id'])
    assert result['status']=='error' and Path(result['retained_workspace']).is_dir()
    assert not Path(run['output_path']).exists()
    assert marker.read_text()=='untouched' and list(external.iterdir())==[marker]
    assert repo.events(run['id'])[-1]['type']=='done'
    following=compiled(runtime);worker.run_once()
    assert repo.run(following['id'])['status']=='success'
