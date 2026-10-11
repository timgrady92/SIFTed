"""Paste analyst CLI examples into Bash without importing the application."""
import csv
import hashlib
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.storage import Repository
from sifted_core.terminal import recipe
from sifted_core.tool_base import OUTPUT, Plan, Settings, Step
from test_zimmerman import zimmerman_runtime as zimmerman_runtime, input_for, queued
from test_sqlite_maps import set_map


def paste(plan, cwd=None, settings=None):
    code = recipe(plan, settings)["terminal_command"]
    syntax = subprocess.run(["bash", "-n"], input=code, text=True, capture_output=True)
    assert syntax.returncode == 0, syntax.stderr
    parent = Path(plan.output_path).parent if plan.output_path != "<output_dir>" else Path.home() / "forensic-results"
    prefix = plan.parameters.get("parser_id") or plan.tool
    existing = set(parent.glob(prefix + ".????????"))
    result = subprocess.run(["bash"], input=code, text=True, capture_output=True, cwd=cwd,
                            env={**os.environ, "PYTHONPATH": ""}, timeout=360)
    outputs = set(parent.glob(prefix + ".????????")) - existing
    assert len(outputs) <= 1
    return result, next(iter(outputs), None)


def plan_for(root, tool, source, **options):
    settings = Settings(input_roots=[str(root)], output_roots=[str(root)], timeout_seconds=120)
    return compile_plan(tool, {"source_path": str(source), "output_path": str(root / "chosen results"), **options},
                        settings, Repository(root / "state.db"), preview=True)[0]


def test_native_strings_are_concise_and_repeated_pastes_preserve_results(tmp_path):
    source = tmp_path / "$(touch injected) `touch injected` 'quotes' ü\nfile.bin"
    source.write_bytes(b"known forensic text\0")
    plan = plan_for(tmp_path, "strings", source)
    chosen = Path(plan.output_path)
    chosen.mkdir()
    (chosen / "original.txt").write_text("preserve this")
    first, output = paste(plan, tmp_path)
    second, repeated = paste(plan, tmp_path)
    assert first.returncode == second.returncode == 0, first.stderr + second.stderr
    assert output != repeated
    assert (output / "strings.txt").read_text() == (repeated / "strings.txt").read_text()
    assert "known forensic text" in (output / "strings.txt").read_text()
    assert (chosen / "original.txt").read_text() == "preserve this"
    assert not (tmp_path / "injected").exists()
    assert source.read_bytes() == b"known forensic text\0"
    code = recipe(plan)["terminal_command"]
    assert 'strings -a -e s -n 4 -t x -- "$evidence"' in code
    assert len(code.splitlines()) <= 16
    for backend_detail in ("sha256sum", "timeout", "trap", "workspace", "SIFT_TERMINAL", "sifted_core", "bash <<"):
        assert backend_detail not in code


def test_native_failure_returns_failure_without_app_validation(tmp_path):
    source = tmp_path / "evidence"
    source.write_text("evidence")
    plan = Plan("false", str(source), str(tmp_path / "out"),
                [Step(["false"], "Fail", OUTPUT + "/partial.txt")])
    result, output = paste(plan)
    assert result.returncode != 0 and (output / "partial.txt").is_file()
    assert "Results:" not in result.stdout


@pytest.mark.parametrize("recursive,expected", [(True, 2), (False, 1)])
def test_file_identification_teaches_file_and_find_with_correct_scope(tmp_path, recursive, expected):
    source = tmp_path / "input directory"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "text.txt").write_text("known text\n")
    (source / "nested/misleading.png").write_bytes((Path(__file__).parent / "samples/images/geotagged.jpg").read_bytes())
    plan = plan_for(tmp_path, "filetype", source, recursive=recursive, mismatch_only=True)
    result, output = paste(plan)
    assert result.returncode == 0, result.stderr
    rows = (output / "filetypes.txt").read_text().splitlines()
    assert len(rows) == expected and any("text.txt:" in row and "text/plain" in row for row in rows)
    if recursive:
        assert any("misleading.png:" in row and "image/jpeg" in row for row in rows)
    assert "find" in recipe(plan)["terminal_command"]
    assert "mismatch filtering" in recipe(plan)["terminal_note"]
    assert "python" not in recipe(plan)["terminal_command"]


@pytest.mark.parametrize("mode,expected", [("mime", "image/jpeg"), ("brief", "JPEG image data"), ("full", "JPEG image data")])
def test_file_identification_retains_filename_and_content_type(tmp_path, mode, expected):
    source = tmp_path / "misleading.png"
    source.write_bytes((Path(__file__).parent / "samples/images/geotagged.jpg").read_bytes())
    result, output = paste(plan_for(tmp_path, "filetype", source, mode=mode))
    assert result.returncode == 0, result.stderr
    assert (str(source) in (output / "filetypes.txt").read_text()) == (mode != "brief")
    assert expected in (output / "filetypes.txt").read_text()


def test_empty_directory_identification_has_an_empty_native_report(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    result, output = paste(plan_for(tmp_path, "filetype", source))
    assert result.returncode == 0 and (output / "filetypes.txt").read_bytes() == b""


def test_sqlite_teaches_native_schema_inspection_and_sql_with_wal(zimmerman_runtime):
    if not shutil.which("sqlite3"):
        pytest.skip("Native sqlite3 is unavailable")
    runtime = zimmerman_runtime
    set_map(runtime, "SELECT value, 9223372036854775807 AS Address, hex(x'00ff012a') AS Data FROM known")
    source = input_for(runtime, "sqlecmd")
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("DELETE FROM known")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO known VALUES('committed WAL terminal marker')")
        connection.commit()
        originals = {p: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (source, Path(str(source) + "-wal"), Path(str(source) + "-shm"))}
        _, plan, _ = queued(runtime, "sqlecmd", source)
        result, output = paste(plan)
        assert result.returncode == 0, result.stderr
        with next(output.glob("query*.csv")).open(newline="") as handle:
            row = next(csv.DictReader(handle))
        assert row == {"value": "committed WAL terminal marker", "Address": "9223372036854775807", "Data": "00FF012A"}
        assert "CREATE TABLE known" in (output / "schema.sql").read_text()
        assert all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p, digest in originals.items())
    code = recipe(plan)["terminal_command"]
    assert "sqlite3 -readonly" in code and ".tables" in code and ".schema" in code
    assert "SELECT value" in code and "cp -p" in code
    for app_detail in ("python", "sqlite-request", "sqlite-maps", "map-summary", "input-before", "native-parameters"):
        assert app_detail not in code


def test_sqlite_cli_rejects_writes_without_altering_original(zimmerman_runtime):
    if not shutil.which("sqlite3"):
        pytest.skip("Native sqlite3 is unavailable")
    set_map(zimmerman_runtime, "DELETE FROM known")
    source = input_for(zimmerman_runtime, "sqlecmd")
    _, plan, _ = queued(zimmerman_runtime, "sqlecmd", source)
    original = source.read_bytes()
    result, _ = paste(plan)
    assert result.returncode != 0 and "readonly" in result.stderr
    assert source.read_bytes() == original


def test_zimmerman_uses_installed_batch_instead_of_embedded_helpers(zimmerman_runtime):
    _, plan, _ = queued(zimmerman_runtime, "recmd", ignore_transaction_logs=True)
    settings = zimmerman_runtime[1]
    code = recipe(plan, settings)["terminal_command"]
    assert str(Path(settings.ez_root) / "RECmd/BatchExamples/RegistryASEPs.reb") in code
    assert "--nl" in code and "cp -p" in code
    for app_detail in ("validate-native", "native-parameters", "--debug", "--dt", "registry-batch.reb", "input/0000"):
        assert app_detail not in code
