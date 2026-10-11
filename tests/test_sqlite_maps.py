"""Real SQLite maps through the durable worker, including WAL, blobs and failures."""

import csv
import hashlib
import sqlite3
from pathlib import Path

import pytest
import yaml

from sifted_core.sqlite_maps import available_maps, load_map
from sifted_core.tool_base import ValidationError
from sifted_core.worker import Worker
from test_zimmerman import zimmerman_runtime as zimmerman_runtime, input_for, queued


def set_map(
    runtime,
    query="SELECT value FROM known",
    identity="SELECT count(*) FROM sqlite_master WHERE name='known'",
    expected=1,
    blobs=None,
):
    profile = {
        "Description": "Known SQLite map",
        "Id": "test-map",
        "CSVPrefix": "Known",
        "FileName": "database.sqlite",
        "IdentifyQuery": identity,
        "IdentifyValue": expected,
        "Queries": [{"Name": "Known rows", "BaseFileName": "Known", "Query": query}],
    }
    if blobs is not None:
        profile["Queries"][0]["BlobColumns"] = blobs
    path = Path(runtime[1].ez_root) / "SQLECmd/Maps/test.smap"
    path.write_text(yaml.safe_dump(profile))
    return path, profile


def finish(runtime, run):
    Worker(runtime[0], runtime[1]).run_once()
    return runtime[0].run(run["id"])


def exported(run):
    path = Path(run["output_path"]) / run["analysis"]["table"]
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def test_known_results_preserve_large_integer_precision_and_original_source(
    zimmerman_runtime,
):
    set_map(
        zimmerman_runtime, "SELECT value, 9223372036854775807 AS Address FROM known"
    )
    source = input_for(zimmerman_runtime, "sqlecmd")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    source.chmod(0o444)
    run, plan, _ = queued(zimmerman_runtime, "sqlecmd", source)
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "success", result.get("error")
    assert exported(result) == [
        {
            "value": "known value",
            "Address": "9223372036854775807",
            "SourceFile": str(source),
        }
    ]
    assert result["analysis"]["engine"] == "SIFTed SQLite maps"
    assert (
        digest
        == result["input_sha256"]
        == hashlib.sha256(source.read_bytes()).hexdigest()
    )
    assert "SQLECmd.dll" not in str(plan.steps[0].argv)


def test_wal_replay_uses_verified_copies_and_preserves_sidecars(zimmerman_runtime):
    source = input_for(zimmerman_runtime, "sqlecmd")
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("DELETE FROM known")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO known VALUES('committed WAL marker')")
        connection.commit()
        files = [source, Path(str(source) + "-wal"), Path(str(source) + "-shm")]
        originals = {str(path): path.read_bytes() for path in files}
        run, plan, _ = queued(zimmerman_runtime, "sqlecmd", source)
        assert set(plan.input_copies) == set(originals)
        result = finish(zimmerman_runtime, run)
        assert result["status"] == "success", result.get("error")
        assert exported(result)[0]["value"] == "committed WAL marker"
        assert all(path.read_bytes() == originals[str(path)] for path in files)
        assert {f["path"] for f in result["input_files"]} == set(originals)


@pytest.mark.parametrize("change", ["add", "remove", "modify"])
def test_sidecar_drift_cannot_execute(zimmerman_runtime, change):
    source = input_for(zimmerman_runtime, "sqlecmd")
    sidecar = Path(str(source) + "-wal")
    if change != "add":
        sidecar.write_bytes(b"recorded sidecar")
    run, _, _ = queued(zimmerman_runtime, "sqlecmd", source)
    if change == "remove":
        sidecar.unlink()
    else:
        sidecar.write_bytes(b"new sidecar")
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "error" and result["steps"] == []


def test_blob_bytes_are_extracted_with_safe_unique_names(zimmerman_runtime):
    source = input_for(zimmerman_runtime, "sqlecmd")
    with sqlite3.connect(source) as connection:
        connection.execute("ALTER TABLE known ADD COLUMN data BLOB")
        connection.execute(
            "UPDATE known SET value='../outside', data=?", (b"\0\xffknown blob",)
        )
    set_map(
        zimmerman_runtime,
        "SELECT value,data FROM known",
        blobs=[{"BlobColumn": "data", "NameColumn": "value", "BlobExtension": "bin"}],
    )
    run, _, _ = queued(zimmerman_runtime, "sqlecmd", source)
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "success", result.get("error")
    row = exported(result)[0]
    blob = Path(result["output_path"]) / row["data"]
    assert blob.parent == Path(result["output_path"]) / "blobs"
    assert blob.read_bytes() == b"\0\xffknown blob"
    assert any(
        f["path"] == str(blob)
        and f["sha256"] == hashlib.sha256(blob.read_bytes()).hexdigest()
        for f in zimmerman_runtime[0].artifacts(run["id"])
    )


@pytest.mark.parametrize(
    "query",
    [
        "DELETE FROM known",
        "ATTACH DATABASE '/tmp/outside.sqlite' AS outside",
        "SELECT load_extension('/tmp/nope')",
        "SELECT readfile('/etc/passwd')",
        "PRAGMA writable_schema=ON",
    ],
)
def test_maps_cannot_write_attach_or_access_external_files(zimmerman_runtime, query):
    source = input_for(zimmerman_runtime, "sqlecmd")
    before = source.read_bytes()
    set_map(zimmerman_runtime, query)
    run, _, _ = queued(zimmerman_runtime, "sqlecmd", source)
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "error", result
    assert source.read_bytes() == before
    assert all(not f["complete"] for f in zimmerman_runtime[0].artifacts(run["id"]))


def test_partial_query_failure_preserves_successful_tables_and_summary(
    zimmerman_runtime,
):
    path, profile = set_map(zimmerman_runtime)
    profile["Queries"].append(
        {
            "Name": "Bad schema",
            "BaseFileName": "Bad",
            "Query": "SELECT missing FROM known",
        }
    )
    path.write_text(yaml.safe_dump(profile))
    run, _, _ = queued(zimmerman_runtime, "sqlecmd")
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "error" and "missing" in result["error"]
    assert result["analysis"]["entry_count"] == 1
    assert [q["status"] for q in result["analysis"]["query_outcomes"]] == [
        "success",
        "error",
    ]
    assert exported(result)[0]["value"] == "known value"


@pytest.mark.parametrize("matched", [True, False])
def test_zero_rows_and_unmatched_profiles_have_explicit_outcomes(
    zimmerman_runtime, matched
):
    set_map(
        zimmerman_runtime,
        "SELECT value FROM known WHERE 0",
        expected=1 if matched else 2,
    )
    run, _, _ = queued(zimmerman_runtime, "sqlecmd")
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "success", result.get("error")
    assert result["analysis"]["entry_count"] == 0
    assert result["analysis"]["query_outcomes"][0]["status"] == (
        "success" if matched else "not_matched"
    )
    assert result["analysis"]["csv_count"] == int(matched)


def test_renamed_database_requires_explicit_map_selection(zimmerman_runtime):
    source = input_for(zimmerman_runtime, "sqlecmd")
    renamed = source.with_name("renamed evidence.bin")
    source.rename(renamed)
    with pytest.raises(ValidationError, match="select a profile explicitly"):
        queued(zimmerman_runtime, "sqlecmd", renamed)
    run, _, _ = queued(zimmerman_runtime, "sqlecmd", renamed, maps=["test.smap"])
    assert finish(zimmerman_runtime, run)["status"] == "success"


def test_all_originals_remain_distinct_unless_deduplication_is_explicit(
    zimmerman_runtime,
):
    source = input_for(zimmerman_runtime, "sqlecmd")
    duplicate = source.parent / "same bytes.sqlite"
    duplicate.write_bytes(source.read_bytes())
    for deduplicate in (False, True):
        run, _, _ = queued(
            zimmerman_runtime,
            "sqlecmd",
            source.parent,
            maps=["test.smap"],
            deduplicate=deduplicate,
        )
        result = finish(zimmerman_runtime, run)
        assert result["status"] == "success", result.get("error")
        assert result["analysis"]["entry_count"] == (1 if deduplicate else 2)


@pytest.mark.parametrize(
    "value",
    [
        "!!python/object/apply:os.system ['false']",
        "Description: first\nDescription: second\n",
        "Id: &x value\nDescription: *x\n",
    ],
)
def test_unsafe_ambiguous_and_aliased_yaml_is_rejected(value):
    with pytest.raises((ValueError, yaml.YAMLError)):
        load_map(value)


def test_invalid_installed_map_is_reported_and_not_silently_activated(
    zimmerman_runtime,
):
    root = Path(zimmerman_runtime[1].ez_root) / "SQLECmd/Maps"
    (root / "invalid.smap").write_text("invalid: map")
    good, bad = available_maps(root)
    assert list(good) == ["test.smap"] and "invalid.smap" in bad
    with pytest.raises(ValidationError, match="valid installed"):
        queued(zimmerman_runtime, "sqlecmd", maps=["invalid.smap"])


def test_map_snapshot_is_used_after_installed_map_changes(zimmerman_runtime):
    path, _ = set_map(zimmerman_runtime)
    run, plan, _ = queued(zimmerman_runtime, "sqlecmd")
    original = path.read_text()
    path.write_text("invalid: changed")
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "success", result.get("error")
    assert (Path(plan.output_path) / "_sifted/maps/test.smap").read_text() == original


def test_localtime_is_deterministically_utc(zimmerman_runtime, monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")
    set_map(
        zimmerman_runtime, "SELECT datetime(1704067200,'unixepoch','localtime') AS Time"
    )
    run, _, _ = queued(zimmerman_runtime, "sqlecmd")
    result = finish(zimmerman_runtime, run)
    assert exported(result)[0]["Time"] == "2024-01-01 00:00:00"
    assert result["analysis"]["timezone"] == "UTC"


def test_expensive_recursive_query_is_interrupted_by_its_own_deadline(
    zimmerman_runtime,
):
    import json
    from sifted_core.adapters import compile_plan
    from test_runtime import enqueue

    set_map(
        zimmerman_runtime,
        "WITH RECURSIVE endless(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM endless) SELECT sum(x) FROM endless",
    )
    source = input_for(zimmerman_runtime, "sqlecmd")
    plan, case, record = compile_plan(
        "eric-zimmerman",
        {
            "tool_id": "sqlecmd",
            "source_path": str(source),
            "output_path": str(zimmerman_runtime[3] / "deadline"),
        },
        zimmerman_runtime[1],
        zimmerman_runtime[0],
    )
    request = json.loads(plan.configs["sqlite-request.json"])
    request["query_seconds"] = 0.05
    plan.configs["sqlite-request.json"] = json.dumps(request)
    result = finish(
        zimmerman_runtime, enqueue(zimmerman_runtime[0], plan, record, case)
    )
    assert (
        result["status"] == "error"
        and result["analysis"]["query_outcomes"][0]["status"] == "error"
    )
    assert "interrupted" in result["analysis"]["query_outcomes"][0]["error"]
    assert all(
        not item["complete"] for item in zimmerman_runtime[0].artifacts(result["id"])
    )


@pytest.mark.parametrize("module", ["fts3", "fts4", "fts5"])
def test_existing_full_text_indexes_can_be_read_without_mutation(
    zimmerman_runtime, module
):
    source = zimmerman_runtime[2] / "database.sqlite"
    with sqlite3.connect(source) as connection:
        connection.execute(f"CREATE VIRTUAL TABLE known USING {module}(value)")
        connection.execute("INSERT INTO known VALUES('known indexed marker')")
    before = source.read_bytes()
    set_map(zimmerman_runtime, "SELECT value FROM known WHERE known MATCH 'marker'")
    run, _, _ = queued(zimmerman_runtime, "sqlecmd", source)
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "success", result.get("error")
    assert exported(result)[0]["value"] == "known indexed marker"
    assert source.read_bytes() == before


def test_hot_rollback_journal_is_recovered_only_in_private_capture(zimmerman_runtime):
    import subprocess
    import sys

    source = input_for(zimmerman_runtime, "sqlecmd")
    code = "import sqlite3,sys,os; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA cache_size=2'); c.execute('BEGIN IMMEDIATE'); c.execute(\"UPDATE known SET value='uncommitted marker'\"); c.executemany('INSERT INTO known VALUES(?)',[('x'*5000,)]*100);os._exit(0)"
    subprocess.run([sys.executable, "-c", code, str(source)], check=True)
    journal = Path(str(source) + "-journal")
    originals = {path: path.read_bytes() for path in (source, journal)}
    assert journal.stat().st_size > 512
    run, plan, _ = queued(zimmerman_runtime, "sqlecmd", source)
    result = finish(zimmerman_runtime, run)
    assert result["status"] == "success", result.get("error")
    assert exported(result) == [{"value": "known value", "SourceFile": str(source)}]
    assert all(path.read_bytes() == data for path, data in originals.items())
    capture = result["analysis"]["capture_outcomes"][0]
    assert (
        capture["rollback_journal_present"]
        and capture["captured_sha256"] != capture["analysis_sha256"]
    )
    assert len(plan.input_copies) == 2 and len(result["input_files"]) == 2
