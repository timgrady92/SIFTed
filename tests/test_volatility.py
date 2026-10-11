"""Volatility discovery, typed plans, partial outcomes and evidence integrity."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from sifted_core import volatility
from sifted_core.adapters import compile_plan
from sifted_core.tool_base import Settings, ValidationError
from sifted_core.viewers import parse_json_table
from sifted_core.tables import ResultTables
from sifted_core.worker import Worker
from test_runtime import enqueue
from sifted_core.storage import Repository


def option(name, kind, required=False, choices=None):
    return {"name": name, "flag": "--" + name.replace("_", "-"), "type": kind,
            "required": required, "choices": choices, "default": None, "description": name}


@pytest.fixture
def memory_runtime(tmp_path, monkeypatch):
    source = tmp_path / 'memory with "quotes".raw'
    source.write_bytes(b"known memory")
    script = tmp_path / "tool.py"
    script.write_text('''import json,sys
from pathlib import Path
a=sys.argv[1:]; out=Path(a[a.index('-o')+1]); plugin=a[a.index('-o')+2]
Path(a[a.index('--save-config')+1]).write_text(json.dumps({'plugin':plugin}))
if '--fail' in a: print('missing symbols',file=sys.stderr); sys.exit(1)
if '--malformed' in a: print('diagnostic, not JSON'); sys.exit(0)
if '--dump' in a: (out/'same-name.bin').write_bytes(plugin.encode())
rows=[{'PID':4,'__children':[{'PID':5,'__children':[]}]}]
fmt=a[a.index('-r')+1]
if fmt=='json': print(json.dumps(rows))
elif fmt=='jsonl':
 for row in rows: print(json.dumps(row))
else: print('PID\\n4')
''')
    catalog = {"windows.pslist.PsList": {"os": "windows", "description": "Processes", "options": [
        option("pid", "integer_list"), option("dump", "boolean"), option("fail", "boolean"),
        option("malformed", "boolean"), option("label", "string"), option("offset", "integer")]},
        "windows.strings.Strings": {"os": "windows", "description": "Strings", "options": [option("strings_file", "file", True)]},
        "linux.pagecache.RecoverFs": {"os": "linux", "description": "Files", "options": [option("dump", "boolean"), option("compression_format", "string", choices=["gz", "xz"])]}}
    installed = {"version": "2.27.0", "plugins": catalog, "identity": "installation-identity",
                 "argv_prefix": [sys.executable, str(script)], "symbol_paths": [], "import_failures": []}
    monkeypatch.setattr(volatility, "discover", lambda settings, refresh=False: installed)
    settings = Settings(input_roots=[str(tmp_path)], output_roots=[str(tmp_path)],
                        volatility_symbols=str(tmp_path / "managed symbols"), timeout_seconds=10)
    return Repository(tmp_path / "runtime.db"), settings, source, installed


def compile_memory(runtime, **options):
    repo, settings, source, _ = runtime
    return compile_plan("volatility", {"source_path": str(source), "output_path": str(source.parent / "results"),
                                      "plugins": ["windows.pslist.PsList"], **options}, settings, repo)


def run_memory(runtime, **options):
    plan, case, record = compile_memory(runtime, **options)
    run = enqueue(runtime[0], plan, record, case)
    Worker(runtime[0], runtime[1]).run_once()
    return runtime[0].run(run["id"]), Path(plan.output_path)


@pytest.mark.parametrize("renderer,count", [("json", 2), ("jsonl", 2), ("pretty", None)])
def test_plugin_outputs_are_validated_and_recorded(memory_runtime, renderer, count):
    run, output = run_memory(memory_runtime, renderer=renderer)
    assert run["status"] == "success", run.get("error")
    assert run["plugin_results"][0]["row_count"] == count
    assert (output / "plugin-summary.json").is_file()
    assert (output / "_sifted/volatility-installation.json").is_file()
    assert Path(memory_runtime[1].volatility_symbols).is_dir()
    assert all(item["complete"] for item in memory_runtime[0].artifacts(run["id"]))


def test_default_symbols_and_exact_preview_are_persisted(memory_runtime):
    plan, _, _ = compile_memory(memory_runtime, plugin_options={"windows.pslist.PsList": {"pid": [4, 123], "label": "--help"}})
    preview, _, _ = compile_plan("volatility", {"source_path": plan.source, "output_path": plan.output_path,
                          "plugins": plan.parameters["plugins"], "plugin_options": plan.parameters["plugin_options"]},
                                memory_runtime[1], memory_runtime[0], preview=True)
    assert plan.steps == preview.steps
    assert "--offline" not in plan.steps[0].argv
    assert "--label=--help" in plan.steps[0].argv
    start = plan.steps[0].argv.index("--pid")
    assert plan.steps[0].argv[start:start+3] == ["--pid", "4", "123"]
    assert plan.parameters["version"] == "2.27.0"


@pytest.mark.parametrize("options", [
    {"plugins": ["windows.pslist"]}, {"plugins": ["--help"]}, {"plugins": "windows.pslist.PsList"},
    {"renderer": "csv"}, {"offline": "false"}, {"plugin_options": []},
    {"plugins": ["windows.strings.Strings"]},
    {"plugin_options": {"unknown.plugin": {}}},
    {"plugin_options": {"windows.pslist.PsList": {"unknown": 1}}},
    {"plugin_options": {"windows.pslist.PsList": {"pid": "4"}}},
    {"plugin_options": {"windows.pslist.PsList": {"pid": [True]}}},
    {"plugin_options": {"windows.pslist.PsList": {"offset": True}}},
    {"plugin_options": {"windows.pslist.PsList": {"dump": "false"}}},
    {"plugins": ["linux.pagecache.RecoverFs"], "plugin_options": {"linux.pagecache.RecoverFs": {"compression_format": "zip"}}},
    {"plugins": ["windows.strings.Strings"], "plugin_options": {"windows.strings.Strings": {"strings_file": "https://example.com/rules"}}},
])
def test_invalid_plugin_requests_never_queue(memory_runtime, options):
    with pytest.raises(ValidationError):
        compile_memory(memory_runtime, **options)
    assert memory_runtime[0].runs() == []


def test_extracted_files_are_isolated_for_each_plugin(memory_runtime):
    run, output = run_memory(memory_runtime, plugins=["windows.pslist.PsList", "linux.pagecache.RecoverFs"],
                            plugin_options={"windows.pslist.PsList": {"dump": True}, "linux.pagecache.RecoverFs": {"dump": True}})
    assert run["status"] == "success"
    assert (output / "plugins/windows.pslist.PsList/same-name.bin").read_bytes() == b"windows.pslist.PsList"
    assert (output / "plugins/linux.pagecache.RecoverFs/same-name.bin").read_bytes() == b"linux.pagecache.RecoverFs"
    assert len(run["plugin_results"]) == 2


@pytest.mark.parametrize("failure", ["fail", "malformed"])
def test_partial_and_invalid_zero_exit_outputs_never_report_success(memory_runtime, failure):
    run, output = run_memory(memory_runtime, plugins=["windows.pslist.PsList", "linux.pagecache.RecoverFs"],
                            plugin_options={"windows.pslist.PsList": {failure: True}})
    assert run["status"] == "error"
    assert [item["status"] for item in run["plugin_results"]] == ["error", "success"]
    assert (output / "plugins/linux.pagecache.RecoverFs/result.json").exists()
    assert all(not item["complete"] for item in memory_runtime[0].artifacts(run["id"]))


@pytest.mark.parametrize("change", [False, True])
def test_auxiliary_inputs_are_hashed_and_rechecked(memory_runtime, change):
    auxiliary = memory_runtime[2].parent / "strings with spaces.txt"
    auxiliary.write_text("4 marker")
    plan, case, record = compile_memory(memory_runtime, plugins=["windows.strings.Strings"],
            plugin_options={"windows.strings.Strings": {"strings_file": str(auxiliary)}})
    assert "--strings-file=" + auxiliary.as_uri() in plan.steps[0].argv
    run = enqueue(memory_runtime[0], plan, record, case)
    if change:
        auxiliary.write_text("changed input")
    Worker(memory_runtime[0], memory_runtime[1]).run_once()
    result = memory_runtime[0].run(run["id"])
    assert result["status"] == ("error" if change else "success")
    if not change:
        item = next(item for item in result["input_files"] if item["path"] == str(auxiliary))
        assert item["sha256"] == hashlib.sha256(auxiliary.read_bytes()).hexdigest()


def test_changed_installation_invalidates_queued_plan(memory_runtime):
    plan, case, record = compile_memory(memory_runtime)
    run = enqueue(memory_runtime[0], plan, record, case)
    memory_runtime[3]["identity"] = "new-installation"
    Worker(memory_runtime[0], memory_runtime[1]).run_once()
    assert "installation changed" in memory_runtime[0].run(run["id"])["error"]


def test_memory_addresses_keep_full_64_bit_precision(memory_runtime):
    address = "0xffff800000123001"
    expected = int(address, 16)
    plan, _, _ = compile_memory(memory_runtime, plugin_options={"windows.pslist.PsList": {"offset": address, "pid": [address]}})
    assert "--offset=" + str(expected) in plan.steps[0].argv
    start = plan.steps[0].argv.index("--pid")
    assert plan.steps[0].argv[start + 1] == str(expected)
    assert plan.parameters["plugin_options"]["windows.pslist.PsList"]["offset"] == expected


def test_discovery_uses_console_scripts_interpreter(tmp_path, monkeypatch):
    launcher = tmp_path / "vol"
    interpreter = str(Path(sys.executable).resolve())
    launcher.write_text("#!" + interpreter + "\nfrom volatility3.cli import main\n")
    launcher.chmod(0o755)
    settings = Settings(binaries={"volatility": str(launcher)})
    calls = []
    def execute(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps({"version": "2.27.0", "plugins": {"banners.Banners": {}},
                            "symbol_paths": [], "import_failures": []}), "")
    monkeypatch.setattr(subprocess, "run", execute)
    result = volatility.discover(settings, refresh=True)
    assert calls[0][:2] == [interpreter, str(volatility.PROBE)]
    assert result["argv_prefix"] == [str(launcher)]
    volatility.discover(settings)
    assert len(calls) == 1


def test_json_lines_table_pages_without_loading_all_rows(tmp_path):
    path = tmp_path / "result.jsonl"
    path.write_text(''.join(json.dumps({"PID": pid}) + "\n" for pid in range(1000)))
    cache = ResultTables(tmp_path / "table-cache.db")
    table, count, truncated = cache.page(path, limit=2, offset=998)
    assert table["rows"] == [["998"], ["999"]]
    assert count == 1000 and not truncated
    path.write_text('{"PID": 42}\n')
    table, count, truncated = cache.page(path)
    assert table["rows"] == [["42"]] and count == 1


@pytest.mark.parametrize("suffix", ["json", "jsonl"])
def test_tree_result_viewer_pages_all_processes(tmp_path, suffix):
    roots = [{"PID": 4, "__children": [{"PID": 5, "__children": []}]}, {"PID": 6, "__children": []}]
    path = tmp_path / ("processes." + suffix)
    path.write_text(json.dumps(roots) if suffix == "json" else "\n" + "\n".join(map(json.dumps, roots)) + "\n")
    if suffix == "jsonl":
        table, count, truncated = ResultTables(tmp_path / "table-cache.db").page(path, limit=1, offset=1)
    else:
        table, count, truncated = parse_json_table(path, row_limit=1, row_offset=1)
    row = dict(zip(table["columns"], table["rows"][0]))
    assert row["PID"] == "5" and row["__depth"] == "1"
    assert "__children" not in table["columns"]
    assert count == 3 and truncated


def test_http_reports_plugin_outcomes_and_serves_complete_tree(memory_runtime, monkeypatch):
    from app import create_app
    from sifted_core import web
    monkeypatch.setattr(web, "discover_volatility", lambda settings: memory_runtime[3])
    repo, settings, source, _ = memory_runtime
    app = create_app({"TESTING": True, "SIFTED_DATABASE_PATH": str(source.parent / "runtime.db"),
                      "SIFTED_INPUT_ROOTS": settings.input_roots, "SIFTED_OUTPUT_ROOTS": settings.output_roots,
                      "SIFTED_VOLATILITY_SYMBOLS": settings.volatility_symbols})
    client = app.test_client()
    assert client.get("/volatility").status_code == 200
    rejected = client.post("/api/volatility/run", json={"source_path": str(source), "output_path": str(source.parent / "results"),
                           "plugins": ["windows.strings.Strings"]})
    assert rejected.status_code == 400 and "requires strings_file" in rejected.json["error"]
    response = client.post("/api/volatility/run", json={"source_path": str(source), "output_path": str(source.parent / "results"),
                           "plugins": ["windows.pslist.PsList"], "renderer": "jsonl"})
    assert response.status_code == 202
    run_id = response.json["run_id"]
    Worker(repo, settings).run_once()
    status = client.get("/api/run/" + run_id + "/status").json
    assert status["status"] == "success" and status["plugin_results"][0]["row_count"] == 2
    results = client.get("/api/run/" + run_id + "/results").json
    assert results["plugin_results"] == status["plugin_results"]
    path = source.parent / "results/plugins/windows.pslist.PsList/result.jsonl"
    view = client.get("/view-file", query_string={"path": str(path)})
    assert view.status_code == 200
    page = client.get("/api/table-rows", query_string={"path": str(path), "offset": 1, "limit": 1})
    assert page.status_code == 200, page.data
    assert page.json["total"] == 2
