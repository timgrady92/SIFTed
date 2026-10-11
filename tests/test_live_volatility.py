"""Real installed Volatility 3; optional pinned public Windows memory image.

See docs/volatility-validation.md for the fixture URL, digest and invocation.
"""
import hashlib
import json
import os
import shutil
import subprocess
import uuid
import threading
import time
from pathlib import Path

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, ValidationError, resolve_argv
from sifted_core.volatility import discover
from sifted_core.worker import Worker
from test_runtime import enqueue


@pytest.fixture
def installed_memory(tmp_path):
    source = tmp_path / "memory with spaces.raw"
    source.write_bytes(b"\0" * 4096 + b"Linux version 6.8.0-sifted-test (synthetic banner) #1 SMP\0" + b"\0" * 4096)
    symbols = tmp_path / "writable symbols"
    settings = Settings(input_roots=[str(tmp_path)], output_roots=[str(tmp_path)],
                        volatility_symbols=str(symbols), timeout_seconds=300)
    try:
        installed = discover(settings)
    except ValidationError as exc:
        if "not installed" in str(exc):
            pytest.skip(str(exc))
        raise
    return Repository(tmp_path / "runtime.db"), settings, source, installed


def submit(runtime, source=None, **options):
    repo, settings, default_source, _ = runtime
    source = source or default_source
    plan, case, record = compile_plan("volatility", {"source_path": str(source),
                        "output_path": str(default_source.parent / uuid.uuid4().hex), **options}, settings, repo)
    run = enqueue(repo, plan, record, case)
    Worker(repo, settings).run_once()
    return repo.run(run["id"]), Path(plan.output_path), plan


@pytest.mark.live
def test_installed_discovery_matches_every_plugins_cli(installed_memory):
    installed = installed_memory[3]
    assert "windows.pslist.PsList" in installed["plugins"]
    assert "windows.malfind.Malfind" not in installed["plugins"]
    assert "windows.ldrmodules.LdrModules" not in installed["plugins"]
    assert "windows.malware.malfind.Malfind" in installed["plugins"]
    for name, spec in installed["plugins"].items():
        result = subprocess.run([*installed["argv_prefix"], name, "--help"], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, name + ": " + result.stderr
        for option in spec["options"]:
            assert option["flag"] in result.stdout, name + ": " + option["flag"]


@pytest.mark.live
@pytest.mark.parametrize("renderer", ["json", "jsonl", "pretty"])
def test_real_generic_scan_needs_no_symbols(installed_memory, renderer):
    run, output, _ = submit(installed_memory, plugins=["banners.Banners"], renderer=renderer, offline=True)
    assert run["status"] == "success", run.get("error")
    suffix = "txt" if renderer == "pretty" else renderer
    assert "Linux version 6.8.0-sifted-test" in (output / "plugins/banners.Banners" / ("result." + suffix)).read_text()
    assert run["plugin_results"][0]["status"] == "success"
    assert run["executables"] and run["input_sha256"]


@pytest.mark.live
@pytest.mark.parametrize("renderer", ["json", "jsonl"])
def test_empty_real_plugin_results_are_valid(installed_memory, renderer):
    installed_memory[2].write_bytes(b"\0" * 8192)
    run, _, _ = submit(installed_memory, plugins=["banners.Banners"], renderer=renderer, offline=True)
    assert run["status"] == "success", run.get("error")
    assert run["plugin_results"][0]["row_count"] == 0


@pytest.mark.live
def test_real_missing_symbols_keep_successful_plugin_results(installed_memory):
    run, output, _ = submit(installed_memory, plugins=["linux.pslist.PsList", "banners.Banners"], offline=True)
    assert run["status"] == "error"
    assert [p["status"] for p in run["plugin_results"]] == ["error", "success"]
    assert "symbol" in run["error"].lower()
    assert (output / "plugin-summary.json").exists()
    assert all(not item["complete"] for item in installed_memory[0].artifacts(run["id"]))


@pytest.fixture
def windows_sample(installed_memory):
    value = os.environ.get("SIFTED_TEST_MEMORY_IMAGE")
    if not value:
        pytest.skip("Set SIFTED_TEST_MEMORY_IMAGE to the documented public Windows sample.")
    source = Path(value).resolve()
    with source.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    assert digest == "c4aeeb1b461378eef796944884d1d60adaa99cbae4d035923c144b08deee1e6e", "Unexpected public memory fixture"
    installed_memory[1].input_roots.append(str(source.parent))
    return source


@pytest.mark.live
def test_real_windows_triage_and_direct_cli_agree(installed_memory, windows_sample):
    plugins = ["windows.info.Info", "windows.pslist.PsList", "windows.pstree.PsTree", "windows.psscan.PsScan",
               "windows.handles.Handles", "windows.dlllist.DllList", "windows.cmdline.CmdLine", "windows.envars.Envars",
               "windows.filescan.FileScan", "windows.registry.hivelist.HiveList", "windows.malware.malfind.Malfind"]
    run, output, plan = submit(installed_memory, source=windows_sample, plugins=plugins)
    assert run["status"] == "success", run.get("error")
    pslist = json.loads((output / "plugins/windows.pslist.PsList/result.json").read_text())
    assert len(pslist) == 47
    assert any(row["PID"] == 1812 and row["ImageFileName"] == "explorer.exe" for row in pslist)
    assert len(run["plugin_results"]) == len(plugins)
    assert all(item["status"] == "success" for item in run["plugin_results"])
    assert next(item for item in run["plugin_results"] if item["plugin"] == "windows.pstree.PsTree")["row_count"] == 47
    for name in ["windows.pslist.PsList", "windows.pstree.PsTree", "windows.dlllist.DllList"]:
        step = next(step for step in plan.steps if step.label == name)
        direct = output.parent / ("direct-" + name)
        direct.mkdir()
        argv = resolve_argv(step.argv, str(direct), str(direct))
        Path(argv[argv.index("-o") + 1]).mkdir(parents=True)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == json.loads((output / "plugins" / name / "result.json").read_text())
    assert list(Path(installed_memory[1].volatility_symbols).rglob("*.json.xz")), "Symbols must download without root access"
    for entry in installed_memory[0].artifacts(run["id"]):
        with open(entry["path"], "rb") as handle:
            assert entry["sha256"] == hashlib.file_digest(handle, "sha256").hexdigest()


@pytest.mark.live
@pytest.mark.parametrize("renderer", ["json", "jsonl", "pretty"])
def test_real_filtered_process_extraction_and_offline_reuse(installed_memory, windows_sample, renderer):
    # Populate this user's writable symbol store, then prohibit further downloads.
    first, _, _ = submit(installed_memory, source=windows_sample, plugins=["windows.info.Info"])
    assert first["status"] == "success", first.get("error")
    run, output, _ = submit(installed_memory, source=windows_sample, plugins=["windows.pslist.PsList", "windows.pstree.PsTree"],
                renderer=renderer, offline=True, plugin_options={"windows.pslist.PsList": {"pid": [1812], "dump": True}})
    assert run["status"] == "success", run.get("error")
    suffix = "txt" if renderer == "pretty" else renderer
    captured = (output / "plugins/windows.pslist.PsList" / ("result." + suffix)).read_text()
    assert "explorer.exe" in captured
    assert "svchost.exe" not in captured
    extracted = [path for path in (output / "plugins/windows.pslist.PsList").iterdir() if path.suffix == ".dmp"]
    assert len(extracted) == 1
    assert extracted[0].read_bytes().startswith(b"MZ")
    assert "--offline" in run["plan"]["steps"][0]["argv"]


@pytest.mark.live
def test_real_strings_plugin_auxiliary_input(installed_memory, windows_sample):
    first, _, _ = submit(installed_memory, source=windows_sample, plugins=["windows.info.Info"])
    assert first["status"] == "success", first.get("error")
    strings = installed_memory[2].parent / "strings with spaces.txt"
    with strings.open("wb") as handle:
        subprocess.run([shutil.which("strings"), "-td", str(windows_sample)], stdout=handle, check=True, timeout=120)
    run, output, _ = submit(installed_memory, source=windows_sample, plugins=["windows.strings.Strings"], offline=True,
                    renderer="jsonl", plugin_options={"windows.strings.Strings": {"strings_file": str(strings), "pid": [1812]}})
    assert run["status"] == "success", run.get("error")
    assert run["plugin_results"][0]["row_count"] > 0
    assert any(item["path"] == str(strings) for item in run["input_files"])
    assert (output / "plugins/windows.strings.Strings/result.jsonl").stat().st_size > 0


@pytest.mark.live
def test_real_memory_scan_can_be_cancelled(installed_memory, windows_sample):
    repo, settings, source, _ = installed_memory
    plan, case, record = compile_plan("volatility", {"source_path": str(windows_sample),
                       "output_path": str(source.parent / "cancelled"), "plugins": ["windows.psscan.PsScan"],
                       "offline": True}, settings, repo)
    run = enqueue(repo, plan, record, case)
    worker = Worker(repo, settings)
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    deadline = time.monotonic() + 30
    process = None
    try:
        while time.monotonic() < deadline:
            state = repo.run(run["id"])
            process = state.get("process")
            if process:
                repo.request_cancel(run["id"])
                break
            if state["status"] not in {"queued", "running"}:
                break
            time.sleep(0.01)
        assert process, "Expected to cancel a running memory scanner"
    finally:
        repo.request_cancel(run["id"])
        thread.join(timeout=30)
    assert not thread.is_alive()
    assert repo.run(run["id"])["status"] == "cancelled"
    assert not Path("/proc", str(process["pid"])).exists()
    assert all(not artifact["complete"] for artifact in repo.artifacts(run["id"]))
