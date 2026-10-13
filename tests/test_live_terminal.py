"""Analyst CLI commands on native SIFT tools, without a running app or worker."""
import csv
import json
import io
import os
import shutil
import shlex
import sqlite3
import subprocess
from pathlib import Path

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.tool_base import ValidationError
from sifted_core.terminal import native_argv, recipe
from test_terminal import paste
from test_live_tools import installed_runtime as installed_runtime
from test_live_disk_tools import disk_runtime as disk_runtime
from test_live_carving import native_carving as native_carving
from test_live_volatility import installed_memory as installed_memory
from test_live_zimmerman import native_zimmerman as native_zimmerman, installed, public_fixture
from tool_fixtures import make_pdf
from zimmerman_samples import TARGET, DELETED_PATH, shortcut, custom_jump_list, recycle_bin, recent_cache

pytestmark = pytest.mark.live


def terminal_plan(runtime, tool, source=None, **options):
    repo, settings, default, outputs = runtime[:4]
    try:
        plan, _, _ = compile_plan(tool, {"source_path": str(source or default), "output_path": str(outputs / "terminal"), **options},
                                  settings, repo, preview=True)
    except ValidationError as exc:
        if "not installed" in str(exc) or "configuration is unavailable" in str(exc):
            pytest.skip(str(exc))
        raise
    required = (["sqlite3"] if plan.parameters.get("parser_id") == "sqlecmd"
                else [native_argv(step.argv)[0] for step in plan.steps])
    for command in required:
        if not shutil.which(command):
            pytest.skip("Required native command is unavailable: " + command)
    return plan


def run_terminal(plan):
    result, output = paste(plan)
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.is_dir()
    return result, output


@pytest.mark.parametrize("tool,options", [
    ("strings", {}), ("strings", {"encoding": "l"}),
    ("exiftool", {"output_format": "csv"}), ("exiftool", {"output_format": "json"}),
    ("filetype", {"mismatch_only": True}), ("bulk-extractor", {"focus_scanners": ["email"]}),
    ("artifact-triage", {"timezone": "UTC"}), ("clamscan", {}),
])
def test_native_generic_terminal_workflows(installed_runtime, tool, options):
    runtime = installed_runtime
    source = runtime[2]
    if tool == "strings":
        source.write_bytes(b"known_ascii_marker\0" + "known_utf16_marker".encode("utf-16-le"))
    elif tool == "filetype":
        source = source.with_suffix(".png")
        shutil.copyfile(runtime[2], source)
    elif tool == "bulk-extractor":
        source.write_bytes(b"known.user@example.com\n" * 1000)
    elif tool == "artifact-triage":
        source = source.with_suffix(".log")
        source.write_text("Jan  1 00:00:01 test-host test-service: known-terminal-marker\n")
    before = source.read_bytes()
    result, output = run_terminal(terminal_plan(runtime, tool, source, **options))
    if tool == "strings":
        assert ("known_utf16_marker" if options else "known_ascii_marker") in result.stdout
    elif tool == "exiftool":
        if options["output_format"] == "json":
            rows = json.loads(result.stdout)
        else:
            rows = list(csv.DictReader(io.StringIO(result.stdout)))
        assert any("TestCamera" in row.values() for row in rows)
    elif tool == "filetype":
        text = result.stdout
        assert str(source) in text and "image/jpeg" in text
    elif tool == "bulk-extractor":
        assert "known.user@example.com" in (output / "bulk-features/email.txt").read_text()
    elif tool == 'artifact-triage':
        assert "known-terminal-marker" in (output / "timeline.csv").read_text()
    else:
        assert 'Scanned files: 1' in result.stdout and 'Infected files: 0' in result.stdout
    assert source.read_bytes() == before and runtime[0].runs() == []


@pytest.mark.parametrize("tool", ["mmls", "fsstat", "fls", "istat", "icat", "blkstat", "blkcat", "blkls", "blkcalc"])
def test_all_native_tsk_terminal_workflows(disk_runtime, tool):
    runtime, disk = disk_runtime
    options = {"offset_sector": disk["offset"]} if tool != "mmls" else {}
    options.update({"fls": {"recursive": True}, "istat": {"metadata_address": disk["inode"]},
                    "icat": {"metadata_address": disk["inode"], "entry_name": "extracted known.bin"},
                    "blkstat": {"block_address": disk["block"]}, "blkcat": {"block_address": disk["block"]},
                    "blkls": {"block_address": disk["free_block"]},
                    "blkcalc": {"block_address": disk["free_block"], "direction": "original_to_unallocated"}}.get(tool, {}))
    result, output = run_terminal(terminal_plan(runtime, tool, **options))
    if tool == "icat":
        assert (output / "extracted known.bin").read_bytes() == disk["payload"]
    elif tool == "blkcat":
        assert (output / "blkcat.bin").read_bytes().startswith(disk["payload"])
    elif tool == "blkls":
        assert (output / "blkls.bin").stat().st_size == 1024
    elif tool == "fls":
        text = result.stdout
        assert "known.bin" in text and "nested/known.pdf" in text
    elif tool == "mmls":
        assert str(disk["offset"]) in result.stdout
    elif tool == "fsstat":
        assert "Ext4" in result.stdout
    elif tool == "istat":
        assert "Allocated" in result.stdout
    elif tool == "blkstat":
        assert "Allocated" in result.stdout
    else:
        assert result.stdout.strip().isdigit()
        assert "blkls" not in recipe(terminal_plan(runtime, tool, **options))["terminal_command"]


@pytest.mark.parametrize("tool", ["head", "xxd", "pdfinfo", "pdftotext"])
def test_native_examination_terminal_workflows(installed_runtime, tool):
    runtime = installed_runtime
    source = runtime[2]
    options = {}
    if tool in {"pdfinfo", "pdftotext"}:
        source = make_pdf(source.with_suffix(".pdf"))
    else:
        source.write_bytes(b"known_text_marker\n" * 1000)
        options = {"byte_limit": 32}
    result, output = run_terminal(terminal_plan(runtime, tool, source, **options))
    data = result.stdout.encode()
    if tool == "head":
        assert data == source.read_bytes()[:32]
    elif tool == "xxd":
        assert data.startswith(b"00000000:") and b"known_text_marke" in data
    elif tool == "pdfinfo":
        assert b"Pages:" in data
    else:
        assert b"Known forensic PDF marker" in data


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_native_carving_terminal_rules_recover_known_bytes(native_carving, tool):
    if not shutil.which(tool):
        pytest.skip(tool + " is not installed")
    runtime = native_carving
    plan = terminal_plan(runtime, tool, types=["png", "gif", "pdf", "zip"])
    result, output = run_terminal(plan)
    assert (output / (tool + "-carved") / "audit.txt").is_file()
    for kind in ("png", "gif", "pdf", "zip"):
        expected = next(data for k, _, data in runtime[4] if k == kind)
        assert any(p.read_bytes() == expected for p in output.rglob("*." + kind))
    if tool == "scalpel":
        rules = (output / "scalpel.conf").read_text()
        assert "png y" in rules and "zip y" in rules
        assert "SIFTed" not in rules
    else:
        assert "-c" not in shlex.split(recipe(plan)["terminal_command"])


@pytest.mark.parametrize("tool,name,data,column,expected", [
    ("lecmd", "known.lnk", shortcut(), "RelativePath", TARGET),
    ("jlecmd", "known.customDestinations-ms", custom_jump_list(), "RelativePath", TARGET),
    ("rbcmd", "$IKNOWN", recycle_bin(), "FileName", DELETED_PATH),
    ("recentfilecacheparser", "RecentFileCache.bcf", recent_cache(), "Filename", DELETED_PATH),
])
def test_native_zimmerman_terminal_known_records(native_zimmerman, tool, name, data, column, expected):
    installed(native_zimmerman, tool)
    source = native_zimmerman[2] / name
    source.write_bytes(data)
    result, output = run_terminal(terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id=tool))
    output = output / (tool + "-csv")
    rows = []
    for p in output.rglob("*.csv"):
        with p.open(newline="", encoding="utf-8-sig") as handle:
            rows.extend(csv.DictReader(handle))
    assert any(row[column] == expected for row in rows)
    assert source.read_bytes() == data


@pytest.mark.parametrize("tool,name,options,count", [
    ("amcacheparser", "Amcache.hve", {}, 166),
    ("appcompatcacheparser", "SYSTEM", {"ignore_transaction_logs": True}, 1024),
    ("recmd", "SYSTEM", {"ignore_transaction_logs": True}, 4157),
    ("evtxecmd", "System.evtx", {}, 5009),
    ("sbecmd", "UsrClass.dat", {"ignore_transaction_logs": True}, 5010),
])
def test_native_zimmerman_terminal_public_artifacts(native_zimmerman, tool, name, options, count):
    installed(native_zimmerman, tool)
    source = public_fixture(native_zimmerman, name)
    if tool == "sbecmd":
        folder = native_zimmerman[2] / "user hives"
        folder.mkdir()
        source.rename(folder / name)
        source = folder
    result, output = run_terminal(terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id=tool, **options))
    output = output / (tool + "-csv")
    rows = []
    for path in output.glob("*.csv"):
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows.extend(csv.DictReader(handle))
    assert len(rows) == count
    assert not (output / "native-summary.json").exists()


def test_native_registry_terminal_replays_logs_on_copies(native_zimmerman):
    installed(native_zimmerman, "recmd")
    source = public_fixture(native_zimmerman, "replay-NTUSER.DAT")
    logs = [public_fixture(native_zimmerman, "replay-NTUSER.DAT." + suffix) for suffix in ("log1", "log2")]
    before = {p: p.read_bytes() for p in [source, *logs]}
    plan = terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id="recmd", batch="UserActivity")
    result, output = paste(plan)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "At least one transaction log was applied" in result.stdout
    assert list((output / "recmd-csv").glob("*.csv"))
    assert all(p.read_bytes() == data for p, data in before.items())


def test_native_mft_terminal_on_real_ntfs_metadata(native_zimmerman):
    installed(native_zimmerman, "mftecmd")
    if not shutil.which("mkfs.ntfs") or not shutil.which("icat"):
        pytest.skip("mkfs.ntfs and icat are required")
    image = native_zimmerman[2] / "ntfs.img"
    with image.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    subprocess.run(["mkfs.ntfs", "-Q", "-F", str(image)], check=True, capture_output=True)
    source = native_zimmerman[2] / "$MFT"
    with source.open("wb") as handle:
        subprocess.run(["icat", str(image), "0"], stdout=handle, stderr=subprocess.PIPE, check=True)
    result, output = run_terminal(terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id="mftecmd"))
    rows = []
    for path in (output / "mftecmd-csv").glob("*.csv"):
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows.extend(csv.DictReader(handle))
    assert any(row.get("FileName") == "$MFT" for row in rows)


def test_native_sqlite_inspection_and_query_on_vanilla_sift(native_zimmerman):
    installed(native_zimmerman, "sqlecmd")
    source = native_zimmerman[2] / "formhistory.sqlite"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE moz_formhistory(id INTEGER,fieldname TEXT,value TEXT,timesUsed INTEGER,firstUsed INTEGER,lastUsed INTEGER,guid TEXT)")
        connection.execute("INSERT INTO moz_formhistory VALUES(1,'search','known terminal sqlite marker',2,1704067200000000,1704153600000000,'known-guid')")
    before = source.read_bytes()
    result, output = run_terminal(terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id="sqlecmd"))
    row = next(csv.DictReader(io.StringIO(result.stdout)))
    assert row["Value"] == "known terminal sqlite marker" and row["First Used"] == "2024-01-01 00:00:00"
    assert source.read_bytes() == before


def test_native_volatility_terminal_offline_banner(installed_memory):
    repo, settings, source, _ = installed_memory
    plan, _, _ = compile_plan("volatility", {"source_path": str(source), "output_path": str(source.parent / "terminal"),
                             "plugins": ["banners.Banners"], "offline": True, "renderer": "jsonl"}, settings, repo, preview=True)
    code = recipe(plan)["terminal_command"]
    assert str(settings.volatility_symbols) not in code and "--save-config" not in code
    assert "mkdir" not in code and " -s " not in code and ">" not in code
    assert "$symbol_dirs" not in code and "export " not in code
    result, output = run_terminal(plan)
    assert "Linux version 6.8.0-sifted-test" in result.stdout


def test_native_volatility_terminal_windows_processes(installed_memory):
    repo, settings, default, _ = installed_memory
    value = os.environ.get("SIFTED_TEST_MEMORY_IMAGE")
    if not value:
        pytest.skip("Set SIFTED_TEST_MEMORY_IMAGE to the documented public Windows memory image")
    source = default.parent / "windows memory.img"
    shutil.copyfile(Path(value).resolve(), source)
    plan, _, _ = compile_plan("volatility", {"source_path": str(source), "output_path": str(default.parent / "terminal"),
                             "plugins": ["windows.pslist.PsList"], "plugin_options": {"windows.pslist.PsList": {"pid": [1812], "dump": True}},
                             "renderer": "jsonl"}, settings, repo, preview=True)
    result, output = run_terminal(plan)
    text = result.stdout
    assert "explorer.exe" in text and "1812" in text
    extracted = list(output.glob("*.dmp"))
    assert extracted and any(path.read_bytes().startswith(b"MZ") for path in extracted)


@pytest.mark.parametrize("tool,name,data,column,expected", [
    ("lecmd", "known.lnk", shortcut(), "RelativePath", TARGET),
    ("jlecmd", "known.customDestinations-ms", custom_jump_list(), "RelativePath", TARGET),
    ("rbcmd", "$IKNOWN", recycle_bin(), "FileName", DELETED_PATH),
])
def test_native_cli_parsers_accept_collected_directories(native_zimmerman, tool, name, data, column, expected):
    installed(native_zimmerman, tool)
    source = native_zimmerman[2] / "collected artifacts"
    for folder in (source, source / "nested"):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(data)
    plan = terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id=tool)
    code = recipe(plan)["terminal_command"]
    assert "-d " + shlex.quote(str(source)) in code
    assert "inputs/0000" not in code and "parser-log.txt" not in code
    result, output = run_terminal(plan)
    output = output / (tool + "-csv")
    rows = []
    for path in output.glob("*.csv"):
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows.extend(csv.DictReader(handle))
    assert sum(row[column] == expected for row in rows) == 2


def test_native_sqlite_cli_handles_multiple_databases_in_a_collection(native_zimmerman):
    installed(native_zimmerman, "sqlecmd")
    source = native_zimmerman[2] / "collected databases"
    originals = {}
    for index in (1, 2):
        folder = source / str(index)
        folder.mkdir(parents=True)
        database = folder / "formhistory.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE moz_formhistory(id INTEGER,fieldname TEXT,value TEXT,timesUsed INTEGER,firstUsed INTEGER,lastUsed INTEGER,guid TEXT)")
            connection.execute("INSERT INTO moz_formhistory VALUES(1,'search',?,2,1704067200000000,1704153600000000,'known-guid')", (f"collection marker {index}",))
        originals[database] = database.read_bytes()
    result, output = run_terminal(terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id="sqlecmd"))
    assert "collection marker 1" in result.stdout and "collection marker 2" in result.stdout
    assert not list(output.glob("query*.csv"))
    assert all(path.read_bytes() == data for path, data in originals.items())


def test_native_registry_cli_replays_logs_in_a_collected_directory(native_zimmerman):
    installed(native_zimmerman, "recmd")
    source = native_zimmerman[2] / "collected hives"
    folder = source / "user"
    folder.mkdir(parents=True)
    originals = {}
    for name in ("replay-NTUSER.DAT", "replay-NTUSER.DAT.log1", "replay-NTUSER.DAT.log2"):
        path = public_fixture(native_zimmerman, name)
        destination = folder / name
        path.rename(destination)
        originals[destination] = destination.read_bytes()
    for path in originals:
        path.chmod(0o444)
    folder.chmod(0o555)
    plan = terminal_plan(native_zimmerman, "eric-zimmerman", source, tool_id="recmd", batch="UserActivity")
    result, output = paste(plan)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "At least one transaction log was applied" in result.stdout
    assert list((output / "recmd-csv").glob("*.csv"))
    assert all(path.read_bytes() == data for path, data in originals.items())
