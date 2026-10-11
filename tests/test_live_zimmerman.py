"""Installed Zimmerman parsers on pinned artifacts and independently known records."""

import csv
import hashlib
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.catalog import EZ_TOOL_CATALOG
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, resolve_argv
from sifted_core.tool_base import ValidationError
from sifted_core.worker import Worker, process_identity
from sifted_core.zimmerman import resolve_ez_tool
from test_runtime import enqueue
from zimmerman_samples import (
    DELETED_PATH,
    TARGET,
    PUBLIC_FIXTURES,
    shortcut,
    recycle_bin,
    recent_cache,
    custom_jump_list,
    hive_header,
)

pytestmark = pytest.mark.live


@pytest.fixture
def native_zimmerman(tmp_path):
    evidence = tmp_path / 'evidence with spaces and "quotes"'
    evidence.mkdir()
    outputs = tmp_path / "parsed outputs"
    outputs.mkdir()
    return (
        Repository(tmp_path / "state.db"),
        Settings(
            input_roots=[str(evidence)],
            output_roots=[str(outputs)],
            timeout_seconds=120,
        ),
        evidence,
        outputs,
    )


def installed(runtime, tool_id):
    tool = resolve_ez_tool(tool_id, runtime[1])
    if not tool["installed"]:
        pytest.skip(tool["error"])
    return tool


def public_fixture(runtime, name):
    directory = os.environ.get("SIFTED_TEST_ZIMMERMAN_FIXTURES")
    if not directory:
        pytest.skip(
            "Set SIFTED_TEST_ZIMMERMAN_FIXTURES to the documented upstream corpus"
        )
    path = Path(directory) / name
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == PUBLIC_FIXTURES[name]
    destination = runtime[2] / name
    destination.write_bytes(data)
    return destination


def queued(runtime, tool_id, source, **options):
    installed(runtime, tool_id)
    plan, case, record = compile_plan(
        "eric-zimmerman",
        {
            "tool_id": tool_id,
            "source_path": str(source),
            "output_path": str(runtime[3] / uuid.uuid4().hex),
            **options,
        },
        runtime[1],
        runtime[0],
    )
    return enqueue(runtime[0], plan, record, case), plan


def execute(runtime, tool_id, source, **options):
    run, plan = queued(runtime, tool_id, source, **options)
    Worker(runtime[0], runtime[1]).run_once()
    result = runtime[0].run(run["id"])
    return result, plan


def rows(result):
    exports = {}
    for table in result["analysis"]["tables"]:
        with (Path(result["output_path"]) / table["file"]).open(
            newline="", encoding="utf-8-sig"
        ) as handle:
            exports[table["file"]] = list(csv.DictReader(handle))
    return exports


def assert_complete(runtime, result):
    assert result["status"] == "success", result.get("error")
    assert result["executables"]
    for item in runtime[0].artifacts(result["id"]):
        assert (
            item["complete"]
            and hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        )
    assert runtime[0].events(result["id"])[-1]["type"] == "done"


def direct_cli_parity(runtime, result, plan):
    base = runtime[3] / ("direct " + result["id"])
    base.mkdir()
    workspace = base / "workspace"
    workspace.mkdir()
    output = base / "output"
    output.mkdir()
    for source, relative in plan.input_copies.items():
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    for name, value in plan.configs.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    for step in plan.steps:
        argv = resolve_argv(step.argv, output, workspace)
        scope = Path(argv[argv.index("--csv") + 1])
        scope.mkdir(parents=True, exist_ok=True)
        run = subprocess.run(argv, capture_output=True, timeout=120, cwd=workspace)
        assert run.returncode == 0, run.stderr.decode(errors="replace")
    managed = Path(result["output_path"])

    def normalized(root):
        tables = {}
        for path in root.rglob("*.csv"):
            if "_sifted" in path.parts:
                continue
            with path.open(newline="", encoding="utf-8-sig") as handle:
                records = list(csv.DictReader(handle))
            values = []
            for row in records:
                row = {
                    k: v
                    for k, v in row.items()
                    if k not in {"SourceCreated", "SourceModified", "SourceAccessed"}
                }
                row = {
                    k: v.replace(str(workspace), "<working>")
                    .replace(str(output), "<output>")
                    .replace(
                        str(runtime[1].output_roots[0])
                        + "/.sifted-staging/"
                        + result["id"],
                        "<working>",
                    )
                    .replace(str(managed), "<output>")
                    .replace("<working>/output", "<output>")
                    for k, v in row.items()
                }
                values.append(
                    {
                        k: re.sub(r"/\d{14}/", "/<export-time>/", v)
                        for k, v in row.items()
                    }
                )
            relative = path.relative_to(root).as_posix()
            tables[re.sub(r"(^|/)\d{14}/", r"\1<export-time>/", relative)] = values
        return tables

    assert normalized(managed) == normalized(output)


@pytest.mark.parametrize(
    "tool_id", [tool for tool in EZ_TOOL_CATALOG if tool != "sqlecmd"]
)
def test_installed_parser_command_interface_is_available(native_zimmerman, tool_id):
    tool = installed(native_zimmerman, tool_id)
    assert tool["version"] and ".dll" in tool["binary_display"]


@pytest.mark.parametrize(
    "tool_id,name,data,column,expected",
    [
        ("lecmd", "known.lnk", shortcut(), "RelativePath", TARGET),
        (
            "jlecmd",
            "known.customDestinations-ms",
            custom_jump_list(),
            "RelativePath",
            TARGET,
        ),
        ("rbcmd", "$IKNOWN", recycle_bin(2), "FileName", DELETED_PATH),
        ("rbcmd", "$IVISTA", recycle_bin(1), "FileName", DELETED_PATH),
        (
            "recentfilecacheparser",
            "RecentFileCache.bcf",
            recent_cache(),
            "Filename",
            DELETED_PATH,
        ),
    ],
)
def test_native_known_records_and_independent_cli(
    native_zimmerman, tool_id, name, data, column, expected
):
    source = native_zimmerman[2] / name
    source.write_bytes(data)
    source.chmod(0o444)
    result, plan = execute(native_zimmerman, tool_id, source)
    assert_complete(native_zimmerman, result)
    records = [row for table in rows(result).values() for row in table]
    assert len(records) == 1 and records[0][column] == expected
    if tool_id == "rbcmd":
        assert (
            records[0]["FileSize"] == "1024"
            and records[0]["DeletedOn"] == "2024-01-01 00:00:00.0000000"
        )
    assert source.read_bytes() == data
    direct_cli_parity(native_zimmerman, result, plan)


@pytest.mark.parametrize(
    "tool_id,name,options,expected_count",
    [
        ("amcacheparser", "Amcache.hve", {}, 166),
        ("appcompatcacheparser", "SYSTEM", {"ignore_transaction_logs": True}, 1024),
        ("recmd", "SYSTEM", {"ignore_transaction_logs": True}, 4157),
        ("evtxecmd", "System.evtx", {}, 5009),
        ("sbecmd", "UsrClass.dat", {"ignore_transaction_logs": True}, 5010),
    ],
)
def test_native_public_artifacts_have_known_results(
    native_zimmerman, tool_id, name, options, expected_count
):
    source = public_fixture(native_zimmerman, name)
    original = source.read_bytes()
    if tool_id == "sbecmd":
        folder = native_zimmerman[2] / "user hive"
        folder.mkdir()
        source.rename(folder / name)
        source = folder
    result, plan = execute(native_zimmerman, tool_id, source, **options)
    assert_complete(native_zimmerman, result)
    records = [row for table in rows(result).values() for row in table]
    assert len(records) == result["analysis"]["entry_count"] == expected_count
    if tool_id == "amcacheparser":
        assert any(
            row.get("SHA1") == "9fa11a63b43f83980e0b48dc9ba2cb59d545a4e8"
            and row.get("Name") == "7z1900-x64.exe"
            for row in records
        )
    if tool_id == "evtxecmd":
        assert records[0]["EventId"] == "7036" and records[0]["Channel"] == "System"
        assert records[0]["TimeCreated"] == "2010-11-21 03:55:59.6264271"
        assert records[0]["MapDescription"] == "Service started or stopped"
    if tool_id == "recmd":
        assert any(
            row["KeyPath"].endswith("\\Select")
            and row["ValueName"] == "Current"
            and row["ValueData"] == "1"
            for row in records
        )
    if tool_id == "sbecmd":
        assert any(row["AbsolutePath"] == "Desktop\\My Computer" for row in records)
    assert (source / name if source.is_dir() else source).read_bytes() == original
    direct_cli_parity(native_zimmerman, result, plan)


def test_directory_duplicates_and_uppercase_names_get_separate_exports(
    native_zimmerman,
):
    source = native_zimmerman[2]
    for folder in ("user one", "user two"):
        directory = source / folder
        directory.mkdir()
        (directory / "same.LNK").write_bytes(shortcut())
    (source / "unrelated.bin").write_bytes(b"unrelated evidence")
    result, plan = execute(native_zimmerman, "lecmd", source)
    assert_complete(native_zimmerman, result)
    assert len(plan.steps) == len(result["analysis"]["tables"]) == 2
    assert result["analysis"]["entry_count"] == 2
    assert len(result["input_files"]) == 3
    direct_cli_parity(native_zimmerman, result, plan)


@pytest.mark.parametrize(
    "tool_id,data,name",
    [
        ("lecmd", shortcut()[:80], "broken.lnk"),
        ("rbcmd", recycle_bin()[:24], "$IBROKEN"),
        ("recentfilecacheparser", recent_cache()[:25], "broken.bcf"),
        ("evtxecmd", b"ElfFile\0" + b"\0" * 512, "broken.evtx"),
        ("recmd", hive_header(), "SYSTEM"),
    ],
)
def test_native_rejected_artifacts_do_not_claim_success(
    native_zimmerman, tool_id, data, name
):
    source = native_zimmerman[2] / name
    source.write_bytes(data)
    try:
        result, _ = execute(native_zimmerman, tool_id, source)
    except ValidationError:
        assert not native_zimmerman[0].runs()
        return
    assert result["status"] == "error", result
    assert all(
        not item["complete"] for item in native_zimmerman[0].artifacts(result["id"])
    )


def test_installed_sqlecmd_maps_execute_on_vanilla_sift(native_zimmerman):
    import sqlite3

    source = native_zimmerman[2] / "formhistory.sqlite"
    with sqlite3.connect(source) as connection:
        connection.execute(
            "CREATE TABLE moz_formhistory(id INTEGER,fieldname TEXT,value TEXT,timesUsed INTEGER,firstUsed INTEGER,lastUsed INTEGER,guid TEXT)"
        )
        connection.execute(
            "INSERT INTO moz_formhistory VALUES(1,'search','known sqlite marker',2,1704067200000000,1704153600000000,'known-guid')"
        )
    before = source.read_bytes()
    result, _ = execute(native_zimmerman, "sqlecmd", source)
    assert_complete(native_zimmerman, result)
    record = next(iter(rows(result).values()))[0]
    assert (
        record["Value"] == "known sqlite marker"
        and record["First Used"] == "2024-01-01 00:00:00"
    )
    assert (
        source.read_bytes() == before
        and result["analysis"]["engine"] == "SIFTed SQLite maps"
    )


def test_native_process_cancellation_retains_captures_and_stops_process(
    native_zimmerman,
):
    source = native_zimmerman[2] / "known.lnk"
    source.write_bytes(shortcut())
    run, _ = queued(native_zimmerman, "lecmd", source)
    worker = Worker(native_zimmerman[0], native_zimmerman[1])
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    pid = None
    try:
        deadline = time.monotonic() + 20
        while thread.is_alive() and time.monotonic() < deadline:
            current = native_zimmerman[0].run(run["id"])
            pid = (current.get("process") or {}).get("pid")
            if pid:
                native_zimmerman[0].request_cancel(run["id"])
                break
            time.sleep(0.005)
        assert pid, "Native parser ended before cancellation could be exercised"
        thread.join(timeout=20)
        assert not thread.is_alive()
    finally:
        worker.stop.set()
        thread.join(timeout=20)
    result = native_zimmerman[0].run(run["id"])
    assert result["status"] == "cancelled" and process_identity(pid) is None
    assert all(
        not item["complete"] for item in native_zimmerman[0].artifacts(run["id"])
    )


def test_native_step_timeout_is_distinct_from_source_verification(native_zimmerman):
    source = native_zimmerman[2] / "known.lnk"
    source.write_bytes(shortcut())
    installed(native_zimmerman, "lecmd")
    plan, case, record = compile_plan(
        "eric-zimmerman",
        {
            "tool_id": "lecmd",
            "source_path": str(source),
            "output_path": str(native_zimmerman[3] / "timeout"),
        },
        native_zimmerman[1],
        native_zimmerman[0],
    )
    plan.steps[0].timeout = 0.01
    run = enqueue(native_zimmerman[0], plan, record, case)
    Worker(native_zimmerman[0], native_zimmerman[1]).run_once()
    result = native_zimmerman[0].run(run["id"])
    assert result["status"] == "error" and result["steps"][0]["return_code"] == 124


def test_native_registry_replays_real_logs_without_changing_originals(native_zimmerman):
    source = public_fixture(native_zimmerman, "replay-NTUSER.DAT")
    logs = [
        public_fixture(native_zimmerman, "replay-NTUSER.DAT." + suffix)
        for suffix in ("log1", "log2")
    ]
    originals = {path: path.read_bytes() for path in [source, *logs]}
    result, plan = execute(native_zimmerman, "recmd", source, batch="UserActivity")
    assert_complete(native_zimmerman, result)
    assert len(plan.input_copies) == len(result["input_files"]) == 3
    log = (Path(result["output_path"]) / "parser-log.txt").read_text()
    assert "At least one transaction log was applied" in log
    assert all(path.read_bytes() == data for path, data in originals.items())
    direct_cli_parity(native_zimmerman, result, plan)


def test_native_recmd_empty_batch_is_a_completed_zero_result(native_zimmerman):
    source = public_fixture(native_zimmerman, "SYSTEM")
    result, plan = execute(
        native_zimmerman,
        "recmd",
        source,
        batch="SoftwareASEPs",
        ignore_transaction_logs=True,
    )
    assert_complete(native_zimmerman, result)
    assert result["analysis"]["entry_count"] == 0 and result["analysis"]["tables"] == []
    assert result["analysis"]["input_outcomes"][0]["status"] == "no_matching_batch_rows"
    direct_cli_parity(native_zimmerman, result, plan)


def test_native_jumplist_directory_preserves_automatic_and_custom_records(
    native_zimmerman,
):
    automatic = public_fixture(
        native_zimmerman, "f01b4d95cf55d32a.automaticDestinations-ms"
    )
    (automatic.parent / "known.customDestinations-ms").write_bytes(custom_jump_list())
    result, plan = execute(
        native_zimmerman,
        "jlecmd",
        automatic.parent,
        include_unlisted=True,
    )
    assert_complete(native_zimmerman, result)
    exports = rows(result)
    assert any(
        name.endswith("AutomaticDestinations.csv") and values
        for name, values in exports.items()
    )
    assert any(
        name.endswith("CustomDestinations.csv") and values[0]["RelativePath"] == TARGET
        for name, values in exports.items()
    )
    direct_cli_parity(native_zimmerman, result, plan)


def test_native_directory_failure_retains_good_input_results(native_zimmerman):
    source = native_zimmerman[2]
    (source / "bad.lnk").write_bytes(shortcut()[:80])
    (source / "good.lnk").write_bytes(shortcut())
    result, _ = execute(native_zimmerman, "lecmd", source)
    assert result["status"] == "error" and result["analysis"]["entry_count"] == 1
    assert len(result["steps"]) == 2
    assert [entry["status"] for entry in result["analysis"]["input_outcomes"]] == [
        "error",
        "exported",
    ]
    assert all(
        not item["complete"] for item in native_zimmerman[0].artifacts(result["id"])
    )


def test_native_shellbags_selects_both_user_hives_and_isolates_same_names(
    native_zimmerman,
):
    ntuser = public_fixture(native_zimmerman, "NTUSER.DAT")
    usrclass = public_fixture(native_zimmerman, "UsrClass.dat")
    second = usrclass.parent / "second user"
    second.mkdir()
    shutil.copyfile(usrclass, second / usrclass.name)
    public_fixture(native_zimmerman, "SYSTEM")
    result, plan = execute(
        native_zimmerman, "sbecmd", ntuser.parent, ignore_transaction_logs=True
    )
    assert_complete(native_zimmerman, result)
    assert len(plan.steps) == 3 and all(
        "SYSTEM" not in path for path in plan.parameters["selected_inputs"]
    )
    assert (
        sum(
            table["entry_count"]
            for table in result["analysis"]["tables"]
            if table["file"].endswith("UsrClass_shellbags.csv")
        )
        == 10020
    )
    assert any(
        table["file"].endswith("NTUSER_shellbags.csv")
        for table in result["analysis"]["tables"]
    )
    direct_cli_parity(native_zimmerman, result, plan)


def test_native_empty_automatic_list_has_a_valid_zero_row_export(native_zimmerman):
    source = public_fixture(native_zimmerman, "automatic.automaticDestinations-ms")
    result, plan = execute(native_zimmerman, "jlecmd", source)
    assert_complete(native_zimmerman, result)
    assert (
        result["analysis"]["entry_count"] == 0 and result["analysis"]["csv_count"] == 1
    )
    direct_cli_parity(native_zimmerman, result, plan)


def test_native_amcache_program_file_option_changes_exported_scope(native_zimmerman):
    source = public_fixture(native_zimmerman, "Amcache.hve")
    result, plan = execute(
        native_zimmerman, "amcacheparser", source, include_program_files=False
    )
    assert_complete(native_zimmerman, result)
    assert result["analysis"]["entry_count"] == 73
    assert "-i" not in plan.steps[0].argv
    direct_cli_parity(native_zimmerman, result, plan)
