"""Execute copied Bash recipes independently of the application and worker."""
import csv
import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.storage import Repository
from sifted_core.terminal import recipe
from sifted_core.tool_base import OUTPUT, WORKSPACE, Plan, Settings, Step
from test_zimmerman import zimmerman_runtime as zimmerman_runtime, input_for, queued
from test_sqlite_maps import set_map


def paste(plan, cwd=None):
    code = recipe(plan)["terminal_command"]
    syntax = subprocess.run(["bash", "-n"], input=code, text=True, capture_output=True)
    assert syntax.returncode == 0, syntax.stderr
    # Exercise the exact text supplied to the browser, with no SIFTed imports.
    result = subprocess.run(["bash"], input=code, text=True, capture_output=True, cwd=cwd,
                            env={**os.environ, "PYTHONPATH": ""}, timeout=360)
    paths = [line.removeprefix("SIFT_TERMINAL_RESULTS=") for line in result.stdout.splitlines()
             if line.startswith("SIFT_TERMINAL_RESULTS=")]
    return result, Path(paths[-1]) if paths else None


def plan_for(root, tool, source, **options):
    settings = Settings(input_roots=[str(root)], output_roots=[str(root)], timeout_seconds=120)
    return compile_plan(tool, {"source_path": str(source), "output_path": str(root / "chosen results"), **options},
                        settings, Repository(root / "state.db"), preview=True)[0]


@pytest.mark.parametrize("output_name", ["chosen results", "a" * 250])
def test_quoted_paths_and_repeat_pastes_preserve_existing_results(tmp_path, output_name):
    source = tmp_path / "$(touch injected) `touch injected` 'quotes' ü\nfile.bin"
    source.write_bytes(b"known forensic text\0")
    plan = plan_for(tmp_path, "strings", source)
    plan.output_path = str(tmp_path / output_name)
    # Existing results created after preview must also survive the terminal run.
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


def test_literal_configuration_is_complete_and_never_interpreted_by_bash(tmp_path):
    source = tmp_path / "evidence"
    source.write_text("evidence")
    config = "$(touch injected)\n`touch injected`\n$HOME\nSIFT_CONFIG_literal\nno final newline"
    plan = Plan("config", str(source), str(tmp_path / "out"),
                [Step(["cat", "--", WORKSPACE + "/nested/rules.conf"], "Read selected configuration", OUTPUT + "/rules.txt")],
                configs={"nested/rules.conf": config})
    result, output = paste(plan, tmp_path)
    assert result.returncode == 0, result.stderr
    assert (output / "rules.txt").read_text() == config
    assert not (tmp_path / "injected").exists()


def test_native_failure_retains_results_and_returns_a_failure(tmp_path):
    source = tmp_path / "evidence"
    source.write_text("evidence")
    plan = Plan("false", str(source), str(tmp_path / "out"),
                [Step(["false"], "Fail", OUTPUT + "/partial.txt")])
    result, output = paste(plan)
    assert result.returncode != 0 and "Step 1 failed" in result.stderr
    assert (output / "partial.txt").is_file()


def test_native_tool_cannot_consume_the_rest_of_the_pasted_script(tmp_path):
    source = tmp_path / "evidence"
    source.write_text("evidence")
    plan = Plan("stdin", str(source), str(tmp_path / "out"),
                [Step(["python3", "-c", "import sys; assert sys.stdin.read() == ''; print('known result')"],
                      "Read closed stdin", OUTPUT + "/result.txt")])
    result, output = paste(plan)
    assert result.returncode == 0, result.stderr
    assert (output / "result.txt").read_text() == "known result\n"


def test_original_evidence_change_is_detected_by_terminal_recipe(tmp_path):
    source = tmp_path / "evidence"
    source.write_text("evidence")
    auxiliary = tmp_path / "auxiliary rules"
    auxiliary.write_text("selected rules")
    plan = Plan("mutation", str(source), str(tmp_path / "out"),
                [Step(["python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('changed')", str(source)], "Simulate evidence drift")],
                auxiliary_paths=[str(auxiliary)])
    result, _ = paste(plan)
    assert result.returncode != 0 and "Evidence changed" in result.stderr


@pytest.mark.parametrize("recursive,mismatch_only,expected", [(True, False, 2), (False, False, 1), (True, True, 1)])
def test_filetype_terminal_report_applies_selected_scope_and_filters(tmp_path, recursive, mismatch_only, expected):
    source = tmp_path / "input directory"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "text.txt").write_text("known text\n")
    (source / "nested/misleading.png").write_bytes((Path(__file__).parent / "samples/images/geotagged.jpg").read_bytes())
    plan = plan_for(tmp_path, "filetype", source, recursive=recursive, mismatch_only=mismatch_only)
    result, output = paste(plan)
    assert result.returncode == 0, result.stderr
    with (output / "filetypes.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == expected
    if recursive:
        row = next(row for row in rows if row["Extension"] == "png")
        assert row["Detected Type"] == "image/jpeg" and row["Mismatch"] == "Yes"


def test_empty_directory_is_a_valid_zero_row_terminal_report(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    result, output = paste(plan_for(tmp_path, "filetype", source))
    assert result.returncode == 0, result.stderr
    with (output / "filetypes.csv").open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []


def test_sqlite_recipe_is_self_contained_with_wal_exact_integers_and_blobs(zimmerman_runtime):
    import sqlite3
    runtime = zimmerman_runtime
    set_map(runtime, "SELECT value, 9223372036854775807 AS Address, x'00ff012a' AS Data FROM known",
            blobs=[{"BlobColumn": "Data", "BlobExtension": "bin"}])
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
        with next(output.glob("*.csv")).open(newline="") as handle:
            row = next(csv.DictReader(handle))
        assert row["value"] == "committed WAL terminal marker" and row["Address"] == "9223372036854775807"
        assert (output / row["Data"]).read_bytes() == b"\0\xff\x01*"
        assert all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p, digest in originals.items())
    assert "sifted_core" not in recipe(plan)["terminal_command"]


def test_sqlite_failed_query_has_nonzero_terminal_exit(zimmerman_runtime):
    set_map(zimmerman_runtime, "DELETE FROM known")
    source = input_for(zimmerman_runtime, "sqlecmd")
    _, plan, _ = queued(zimmerman_runtime, "sqlecmd", source)
    original = source.read_bytes()
    result, output = paste(plan)
    assert result.returncode != 0 and "not authorized" in result.stderr
    assert (output / "map-summary.json").is_file() and source.read_bytes() == original
