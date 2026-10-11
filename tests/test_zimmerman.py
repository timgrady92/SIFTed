"""Parser contracts, native failures, frozen configuration and evidence dependencies."""

import hashlib
import json
import sys
import sqlite3
import uuid
from pathlib import Path

import pytest

from app import create_app
from sifted_core.adapters import compile_plan
from sifted_core.catalog import EZ_TOOL_CATALOG
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, ValidationError
from sifted_core.worker import Worker
from sifted_core.zimmerman import resolve_ez_tool
from sifted_core.zimmerman_exports import REQUIRED_COLUMNS
from test_runtime import enqueue
from zimmerman_samples import (
    custom_jump_list,
    hive_header,
    event_header,
    recent_cache,
    recycle_bin,
    shortcut,
)


@pytest.fixture
def zimmerman_runtime(tmp_path):
    evidence = tmp_path / 'evidence with spaces and "quotes"'
    evidence.mkdir()
    output = tmp_path / "results"
    output.mkdir()
    root = tmp_path / "EZ installation"
    batch = root / "RECmd/BatchExamples/RegistryASEPs.reb"
    batch.parent.mkdir(parents=True)
    batch.write_text("Description: Test profile\nKeys: []\n")
    for family, suffix in (("EvtxeCmd", ".map"), ("SQLECmd", ".smap")):
        maps = root / family / "Maps"
        maps.mkdir(parents=True)
        (maps / ("test" + suffix)).write_text(
            "Description: Test map\n"
            if suffix == ".map"
            else """Description: Test map
Id: test-map
CSVPrefix: Test
FileName: database.sqlite
IdentifyQuery: SELECT count(*) FROM sqlite_master WHERE name='known';
IdentifyValue: 1
Queries:
  - Name: Known values
    Query: SELECT value FROM known;
    BaseFileName: Known
"""
        )
    script = tmp_path / "native parser.py"
    schemas = {tool: sorted(columns) for tool, columns in REQUIRED_COLUMNS.items()}
    schemas["amcacheparser"] = ["FullPath", "SHA1"]
    script.write_text(
        """import csv,json,sys
from pathlib import Path
tool,*args=sys.argv[1:]
if '-h' in args:
 print('Test parser version 1.0.0')
 for option in ['-f','-d','-q','--csv','--csvf','--debug','--dt','--nl','-i','--withDir','--recover','--dedupe','--bn','--maps']:
  print('  '+option+' <value>')
 sys.exit()
output=Path(args[args.index('--csv')+1]);output.mkdir(exist_ok=True)
name=args[args.index('--csvf')+1]
if tool=='amcacheparser':name=name.replace('.csv','_UnassociatedFileEntries.csv')
if tool=='jlecmd':name=name.replace('.csv','_AutomaticDestinations.csv')
if tool=='sbecmd':name='NTUSER_'+name
schemas="""
        + repr(schemas)
        + """
columns=schemas[tool]
with (output/name).open('w',newline='') as handle:
 writer=csv.writer(handle);writer.writerow(columns);writer.writerow(['known value']*len(columns))
print('Native processing completed')
"""
    )
    settings = Settings(
        input_roots=[str(evidence)],
        output_roots=[str(output)],
        ez_root=str(root),
        binaries={
            tool: [sys.executable, str(script), tool]
            for tool in EZ_TOOL_CATALOG
            if tool != "sqlecmd"
        },
        timeout_seconds=10,
    )
    return Repository(tmp_path / "runtime.db"), settings, evidence, output, script


def input_for(runtime, tool_id):
    evidence = runtime[2]
    name, data = {
        "amcacheparser": ("Amcache.hve", hive_header()),
        "appcompatcacheparser": ("SYSTEM", hive_header()),
        "recmd": ("SYSTEM", hive_header()),
        "sbecmd": ("NTUSER.DAT", hive_header()),
        "lecmd": ("known.lnk", shortcut()),
        "jlecmd": ("known.customDestinations-ms", custom_jump_list()),
        "rbcmd": ("$IKNOWN", recycle_bin()),
        "recentfilecacheparser": ("RecentFileCache.bcf", recent_cache()),
        "evtxecmd": ("System.evtx", event_header()),
        "mftecmd": ("$MFT", b"FILE" + b"\0" * 1020),
        "sqlecmd": ("database.sqlite", b"SQLite format 3\0" + b"\0" * 512),
    }[tool_id]
    source = evidence / name
    if tool_id == "sqlecmd":
        with sqlite3.connect(source) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS known(value TEXT)")
            connection.execute("DELETE FROM known")
            connection.execute("INSERT INTO known VALUES('known value')")
        return source
    source.write_bytes(data)
    return evidence if tool_id == "sbecmd" else source


def queued(runtime, tool_id, source=None, **options):
    repo, settings, _, outputs, _ = runtime
    payload = {
        "tool_id": tool_id,
        "source_path": str(source or input_for(runtime, tool_id)),
        "output_path": str(outputs / uuid.uuid4().hex),
        **options,
    }
    plan, case, record = compile_plan("eric-zimmerman", payload, settings, repo)
    return enqueue(repo, plan, record, case), plan, payload


@pytest.mark.parametrize("tool_id", list(EZ_TOOL_CATALOG))
def test_parser_specific_exports_use_common_queue_and_native_interface(
    zimmerman_runtime, tool_id
):
    repo, settings, _, _, _ = zimmerman_runtime
    run, plan, payload = queued(zimmerman_runtime, tool_id)
    preview, _, _ = compile_plan(
        "eric-zimmerman", payload, settings, repo, preview=True
    )
    assert preview.steps[0].argv == plan.steps[0].argv
    Worker(repo, settings).run_once()
    completed = repo.run(run["id"])
    assert completed["status"] == "success", completed.get("error")
    assert completed["analysis"]["entry_count"] == 1
    assert completed["analysis"]["parser_id"] == tool_id
    for artifact in repo.artifacts(run["id"]):
        assert (
            artifact["complete"]
            and artifact["sha256"]
            == hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest()
        )
    assert repo.events(run["id"])[-1]["type"] == "done"


@pytest.mark.parametrize("tool_id", list(EZ_TOOL_CATALOG))
def test_wrong_input_cannot_create_a_job(zimmerman_runtime, tool_id):
    source = zimmerman_runtime[2] / "wrong.bin"
    source.write_bytes(b"not this artifact")
    if tool_id == "sbecmd":
        source = source.parent
    with pytest.raises(ValidationError):
        queued(zimmerman_runtime, tool_id, source)
    assert not zimmerman_runtime[0].runs()


@pytest.mark.parametrize(
    "mode",
    [
        "logs_absent",
        "log_changed",
        "log_added",
        "log_removed",
        "log_symlink",
        "ambiguous_logs",
    ],
)
def test_registry_transaction_dependencies_are_explicit(zimmerman_runtime, mode):
    repo, settings, evidence, _, _ = zimmerman_runtime
    source = evidence / "SYSTEM"
    source.write_bytes(hive_header(dirty=True))
    log = evidence / "system.log1"
    if mode != "logs_absent":
        log.write_bytes(b"regf" + b"\0" * 508)
    if mode == "log_symlink":
        log.unlink()
        log.symlink_to(source)
    if mode == "ambiguous_logs":
        (evidence / "SYSTEM.LOG1").write_bytes(b"duplicate")
    if mode in {"logs_absent", "log_symlink", "ambiguous_logs"}:
        with pytest.raises(ValidationError):
            queued(zimmerman_runtime, "recmd", source)
        return
    run, plan, _ = queued(zimmerman_runtime, "recmd", source)
    assert plan.input_copies[str(log)] == "input/SYSTEM.LOG1"
    assert repo.input(run["id"])["related_files"][0]["path"] == str(log)
    if mode == "log_changed":
        log.write_bytes(b"changed log")
    if mode == "log_removed":
        log.unlink()
    if mode == "log_added":
        (evidence / "SYSTEM.LOG2").write_bytes(b"added log")
    Worker(repo, settings).run_once()
    failed = repo.run(run["id"])
    assert failed["status"] == "error" and not failed["steps"]


def test_explicit_ignore_logs_is_visible_in_plan_and_analysis(zimmerman_runtime):
    repo, settings, evidence, _, _ = zimmerman_runtime
    source = evidence / "SYSTEM"
    source.write_bytes(hive_header(dirty=True))
    run, plan, _ = queued(
        zimmerman_runtime, "recmd", source, ignore_transaction_logs=True
    )
    assert "--nl" in plan.steps[0].argv
    Worker(repo, settings).run_once()
    assert repo.run(run["id"])["analysis"]["ignore_transaction_logs"]


@pytest.mark.parametrize("changed", ["installation", "config"])
def test_queue_freezes_configuration_and_rejects_changed_installation(
    zimmerman_runtime, changed
):
    repo, settings, _, _, script = zimmerman_runtime
    run, plan, _ = queued(zimmerman_runtime, "evtxecmd")
    if changed == "installation":
        script.write_text(script.read_text() + "\n# different installation\n")
    else:
        (Path(settings.ez_root) / "EvtxeCmd/Maps/test.map").write_text("Changed map\n")
    Worker(repo, settings).run_once()
    completed = repo.run(run["id"])
    if changed == "installation":
        assert (
            completed["status"] == "error"
            and "installation changed" in completed["error"]
            and not completed["steps"]
        )
    else:
        assert completed["status"] == "success", completed.get("error")
        assert (
            Path(plan.output_path) / "_sifted/maps/test.map"
        ).read_text() == "Description: Test map\n"


@pytest.mark.parametrize(
    "content,error",
    [
        ("Name,Value\nnot,an event\n", "required columns"),
        (
            "EventId,RecordNumber,TimeCreated,Provider,Channel\n1,2,3,4,5,6\n",
            "column count",
        ),
        ("EventId,EventId\n1,2\n", "duplicate columns"),
        ("", "empty or duplicate"),
    ],
)
def test_exit_zero_cannot_validate_wrong_csv(zimmerman_runtime, content, error):
    repo, settings, _, _, script = zimmerman_runtime
    script.write_text(
        script.read_text() + "\n(output/name).write_text(" + repr(content) + ")\n"
    )
    run, _, _ = queued(zimmerman_runtime, "evtxecmd")
    Worker(repo, settings).run_once()
    failed = repo.run(run["id"])
    assert failed["status"] == "error" and error in failed["error"]
    assert all(not f["complete"] for f in repo.artifacts(run["id"]))


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize(
    "message",
    [
        "[12:00:00.000 ERR] Artifact rejected",
        "[2026-10-11 12:00:00.1234567 ERR] Incomplete artifact",
        "Unhandled exception: invalid parser",
        "Message: Error parsing shellbag Type: incomplete",
    ],
)
def test_native_errors_fail_even_with_valid_csv_and_zero_exit(
    zimmerman_runtime, message, stream
):
    repo, settings, _, _, script = zimmerman_runtime
    script.write_text(
        script.read_text() + "\nprint(" + repr(message) + ", file=sys." + stream + ")\n"
    )
    run, _, _ = queued(zimmerman_runtime, "evtxecmd")
    Worker(repo, settings).run_once()
    failed = repo.run(run["id"])
    assert failed["status"] == "error" and "incomplete processing" in failed["error"]
    assert (Path(failed["output_path"]) / "eventlogs.csv").exists()


def test_missing_csv_and_missing_primary_batch_are_failures(zimmerman_runtime):
    repo, settings, _, _, script = zimmerman_runtime
    script.write_text(script.read_text() + "\n(output/name).unlink()\n")
    run, _, _ = queued(zimmerman_runtime, "recmd")
    Worker(repo, settings).run_once()
    assert "no primary CSV exports" in repo.run(run["id"])["error"]


def test_native_wrapper_is_not_a_fallback(zimmerman_runtime, monkeypatch):
    settings = zimmerman_runtime[1]
    settings.binaries.clear()
    monkeypatch.setattr(
        "sifted_core.zimmerman.shutil.which", lambda name: "/usr/bin/" + name
    )
    tool = resolve_ez_tool("lecmd", settings)
    assert not tool["installed"] and "LECmd.dll" in tool["error"]


def test_parser_options_are_specific_and_real(zimmerman_runtime):
    with pytest.raises(ValidationError, match="Unsupported options"):
        queued(zimmerman_runtime, "lecmd", recover_deleted=True)
    with pytest.raises(ValidationError, match="Unsupported options"):
        queued(zimmerman_runtime, "evtxecmd", deduplicate=True)
    run, plan, _ = queued(zimmerman_runtime, "evtxecmd")
    args = plan.steps[0].argv
    assert args[args.index("--dedupe") + 1] == "false"


def test_capability_and_options_are_rendered_from_current_parser(zimmerman_runtime):
    repo, settings, evidence, _, _ = zimmerman_runtime
    app = create_app(
        {
            "TESTING": True,
            "SIFTED_DATABASE_PATH": str(repo.path),
            "SIFTED_INPUT_ROOTS": settings.input_roots,
            "SIFTED_OUTPUT_ROOTS": settings.output_roots,
            "SIFTED_EZ_ROOT": settings.ez_root,
            "SIFTED_BINARIES": settings.binaries,
        }
    )
    page = app.test_client().get("/eric-zimmerman")
    assert (
        page.status_code == 200
        and b"ezToolOptions" in page.data
        and b"registry transaction logs" in page.data
    )
    data = page.data.decode().split('id="ezToolData">')[1].split("</script>")[0]
    tools = {t["id"]: t for t in json.loads(data)}
    assert tools["recmd"]["installed"] and tools["recmd"]["options"][0]["choices"] == [
        "RegistryASEPs"
    ]


def test_directory_failure_preserves_valid_tables_and_reports_each_input(
    zimmerman_runtime,
):
    source = zimmerman_runtime[2]
    for name in ("bad.lnk", "good.lnk"):
        (source / name).write_bytes(shortcut())
    script = zimmerman_runtime[4]
    script.write_text(
        "import sys\nif '-f' in sys.argv and sys.argv[sys.argv.index('-f')+1].endswith('bad.lnk'):\n print('[2026-10-11 14:30:01.1234567 ERR] known parse failure',file=sys.stderr);sys.exit(17)\n"
        + script.read_text()
    )
    run, _, _ = queued(zimmerman_runtime, "lecmd", source)
    Worker(zimmerman_runtime[0], zimmerman_runtime[1]).run_once()
    result = zimmerman_runtime[0].run(run["id"])
    assert result["status"] == "error" and len(result["steps"]) == 2
    assert result["analysis"]["entry_count"] == 1
    assert [outcome["status"] for outcome in result["analysis"]["input_outcomes"]] == [
        "error",
        "exported",
    ]
    assert "known parse failure" in result["error"]
    assert all(
        not item["complete"] for item in zimmerman_runtime[0].artifacts(run["id"])
    )


def test_evtx_record_errors_in_information_summary_are_not_success(zimmerman_runtime):
    script = zimmerman_runtime[4]
    script.write_text(
        script.read_text()
        + "\nprint('[2026-10-11 14:30:01.1234567 INF] Records included: 1 Errors: 2 Events dropped: 0')\n"
    )
    run, _, _ = queued(zimmerman_runtime, "evtxecmd")
    Worker(zimmerman_runtime[0], zimmerman_runtime[1]).run_once()
    result = zimmerman_runtime[0].run(run["id"])
    assert result["status"] == "error" and "Errors: 2" in result["error"]
    assert result["analysis"]["entry_count"] == 1


def test_discovery_rejects_missing_required_native_options(zimmerman_runtime):
    script = zimmerman_runtime[4]
    script.write_text(script.read_text().replace("'--csvf',", ""))
    tool = resolve_ez_tool("lecmd", zimmerman_runtime[1])
    assert not tool["installed"] and "--csvf" in tool["error"]


def test_explicit_unavailable_executable_has_a_useful_error(zimmerman_runtime):
    zimmerman_runtime[1].binaries["lecmd"] = ["/does/not/exist/LECmd"]
    tool = resolve_ez_tool("lecmd", zimmerman_runtime[1])
    assert not tool["installed"] and "lecmd" in tool["error"]
