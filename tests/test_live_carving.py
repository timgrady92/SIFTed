"""Native SIFT carvers: exact recoveries, CLI parity, flags, limits and follow-ups."""

import csv
import hashlib
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from app import create_app
from carving_samples import mixed_image, samples
from sifted_core.adapters import compile_plan
from sifted_core.carving import FOREMOST_TYPES
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, ValidationError, resolve_argv
from sifted_core.viewers import parse_carving_audit
from sifted_core.worker import Worker, process_identity
from test_runtime import enqueue

pytestmark = pytest.mark.live


@pytest.fixture
def native_carving(tmp_path):
    evidence = tmp_path / "evidence with spaces"
    evidence.mkdir()
    output = tmp_path / "results with spaces"
    output.mkdir()
    source = evidence / 'image with "quotes".dd'
    expected = mixed_image(source)
    settings = Settings(
        input_roots=[str(evidence)], output_roots=[str(output)], timeout_seconds=120
    )
    return Repository(tmp_path / "runtime.db"), settings, source, output, expected


def queued(runtime, tool, source=None, **options):
    if not shutil.which(tool):
        pytest.skip(tool + " is not installed")
    repo, settings, default_source, outputs, _ = runtime
    data = {
        "source_path": str(source or default_source),
        "output_path": str(outputs / uuid.uuid4().hex),
        "types": ["jpg", "png", "gif", "pdf", "zip"],
        **options,
    }
    plan, case, record = compile_plan(tool, data, settings, repo)
    run = enqueue(repo, plan, record, case)
    return run, plan


def execute(runtime, tool, source=None, **options):
    run, plan = queued(runtime, tool, source, **options)
    Worker(runtime[0], runtime[1]).run_once()
    return runtime[0].run(run["id"]), Path(plan.output_path), plan


def recoveries(output):
    with (output / "carved.csv").open(newline="") as handle:
        return list(csv.DictReader(handle))


def assert_verified(runtime, run, output):
    assert run["status"] == "success", run.get("error")
    assert run["executables"]
    assert (
        run["input_sha256"]
        == hashlib.sha256(Path(run["plan"]["source"]).read_bytes()).hexdigest()
    )
    for item in runtime[0].artifacts(run["id"]):
        assert (
            item["complete"]
            and hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        )


@pytest.mark.parametrize(
    "tool,options",
    [
        ("foremost", {}),
        ("foremost", {"verbose": True}),
        ("scalpel", {"organize": True}),
        ("scalpel", {"organize": False}),
    ],
)
def test_mixed_files_exact_bytes_duplicate_headers_offsets_and_direct_cli(
    native_carving, tool, options
):
    repo, settings, source, outputs, expected = native_carving
    original = source.read_bytes()
    source.chmod(0o444)
    run, output, plan = execute(native_carving, tool, **options)
    assert_verified(native_carving, run, output)
    rows = recoveries(output)
    actual = sorted(
        (r["Type"], int(r["Offset Bytes"]), (output / r["File"]).read_bytes())
        for r in rows
    )
    assert actual == sorted(expected)
    assert run["file_count"] == len(expected) == 7
    assert source.read_bytes() == original
    for row in rows:
        assert (
            row["SHA-256"]
            == hashlib.sha256((output / row["File"]).read_bytes()).hexdigest()
        )
        if tool == "scalpel" and not options["organize"]:
            assert "/" not in row["File"]
    # A separate direct invocation uses the persisted config and independent destination.
    workspace = outputs / "direct workspace"
    workspace.mkdir()
    for name, content in plan.configs.items():
        (workspace / name).write_text(content)
    direct = outputs / "direct output"
    result = subprocess.run(
        resolve_argv(plan.steps[0].argv, direct, workspace),
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    files = lambda root: sorted(
        (p.relative_to(root).as_posix(), p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
        and p.name != "audit.txt"
        and "_sifted" not in p.parts
        and p.name != "carved.csv"
    )
    assert files(output) == files(direct)
    # Audits display byte offsets, never their row number or filename's 512-byte block.
    table, total, _ = parse_carving_audit(output / "audit.txt")
    assert total == 7 and sorted(int(r[1]) for r in table["rows"]) == sorted(
        e[1] for e in expected
    )
    app = create_app(
        {
            "TESTING": True,
            "SIFTED_DATABASE_PATH": str(repo.path),
            "SIFTED_INPUT_ROOTS": settings.input_roots,
            "SIFTED_OUTPUT_ROOTS": settings.output_roots,
        }
    )
    client = app.test_client()
    page = client.get("/run/" + run["id"] + "/analysis")
    assert page.status_code == 200 and b"View recovered file" in page.data
    assert (
        client.get(
            "/view-file",
            query_string={"path": str(output / "audit.txt"), "view": "table"},
        ).status_code
        == 200
    )
    assert client.get("/api/run/" + run["id"] + "/results").json["analysis_url"]


@pytest.mark.parametrize("kind", ["jpg", "png", "gif", "pdf", "zip", "bmp", "exe"])
def test_foremost_structure_aware_recovery_of_known_formats(native_carving, kind):
    source = native_carving[2]
    expected = mixed_image(source, types=(kind,), duplicate=False)
    run, output, _ = execute(native_carving, "foremost", types=[kind])
    assert_verified(native_carving, run, output)
    rows = recoveries(output)
    assert len(rows) == 1, (kind, (output / "audit.txt").read_text())
    row = rows[0]
    assert int(row["Offset Bytes"]) == expected[0][1]
    assert (output / row["File"]).read_bytes() == expected[0][2]


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
@pytest.mark.parametrize("size", [0, 8192])
def test_empty_and_no_matching_images_are_successful_zero_recoveries(
    native_carving, tool, size
):
    native_carving[2].write_bytes(b"\0" * size)
    run, output, _ = execute(native_carving, tool)
    assert_verified(native_carving, run, output)
    assert run["file_count"] == 0 and recoveries(output) == []
    assert parse_carving_audit(output / "audit.txt")[1] == 0


@pytest.mark.parametrize("kind", FOREMOST_TYPES)
def test_every_exposed_foremost_selector_is_accepted_by_native_sift(
    native_carving, kind
):
    native_carving[2].write_bytes(b"\0" * 8192)
    run, output, _ = execute(native_carving, "foremost", types=[kind])
    assert_verified(native_carving, run, output)
    assert recoveries(output) == []


def test_foremost_boundary_only_scan_explicitly_misses_unaligned_headers(
    native_carving,
):
    source = native_carving[2]
    data = samples()["png"]
    source.write_bytes(
        b"\0" * 512 + data + b"\0" * (1024 - 512 - len(data) + 7) + data + b"\0" * 512
    )
    full, full_output, _ = execute(native_carving, "foremost", types=["png"])
    quick, quick_output, _ = execute(
        native_carving, "foremost", types=["png"], quick=True
    )
    assert_verified(native_carving, full, full_output)
    assert_verified(native_carving, quick, quick_output)
    assert [int(r["Offset Bytes"]) for r in recoveries(full_output)] == [512, 1031]
    assert [int(r["Offset Bytes"]) for r in recoveries(quick_output)] == [512]
    assert quick["analysis"]["quick"]


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_truncated_headers_are_not_silently_reported_as_complete_original_files(
    native_carving, tool
):
    source = native_carving[2]
    source.write_bytes(b"\0" * 512 + samples()["jpg"][:-2])
    run, output, _ = execute(native_carving, tool, types=["jpg"])
    assert_verified(native_carving, run, output)
    assert recoveries(output) == []


def test_scalpel_custom_wildcard_case_and_search_directions_are_faithful(
    native_carving,
):
    repo, settings, source, outputs, _ = native_carving
    source.write_bytes(b"\0" * 512 + b"heaDz-one-END-two-END" + b"\0" * 512)
    config = outputs / "custom.conf"
    config.write_text(
        r"wildcard \x40"
        + "\nforward n 30 HEAD@ END\nreverse n 30 HEAD@ END REVERSE\nnext n 30 HEAD@ END NEXT\n#commented n 30 HEAD@ END\n"
    )
    settings.scalpel_config = str(config)
    run, output, _ = execute(
        native_carving, "scalpel", types=["forward", "reverse", "next"]
    )
    assert_verified(native_carving, run, output)
    actual = {r["Type"]: (output / r["File"]).read_bytes() for r in recoveries(output)}
    assert actual == {
        "forward": b"heaDz-one-END",
        "reverse": b"heaDz-one-END-two-END",
        "next": b"heaDz-one-",
    }


def test_scalpel_custom_footerless_rules_report_chopped_ranges(native_carving):
    _, settings, source, outputs, _ = native_carving
    source.write_bytes(b"\0" * 512 + b"HEADabcdefghijklmno")
    config = outputs / "footerless.conf"
    config.write_text("raw y 8 HEAD\nNONE y 8 HEAD\n")
    settings.scalpel_config = str(config)
    run, output, _ = execute(
        native_carving, "scalpel", types=["raw", "NONE"], organize=False
    )
    assert_verified(native_carving, run, output)
    rows = recoveries(output)
    assert len(rows) == 2 and {row["Type"] for row in rows} == {"raw", ""}
    for row in rows:
        assert (output / row["File"]).read_bytes() == b"HEADabcd" and row[
            "Chopped"
        ] == "YES"
    assert run["analysis"]["chopped_count"] == 2


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_budget_failure_preserves_incomplete_native_recoveries(native_carving, tool):
    native_carving[1].max_output_bytes = 1000
    run, output, _ = execute(native_carving, tool)
    assert run["status"] == "error" and "budget" in run["error"]
    assert output.exists() and all(
        not f["complete"] for f in native_carving[0].artifacts(run["id"])
    )


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_cancelling_actual_native_carver_kills_process_and_preserves_captures(
    native_carving, tool
):
    source = native_carving[2]
    with source.open("wb") as handle:
        handle.truncate(1024**3)
    queued_run, plan = queued(native_carving, tool, types=["jpg"])
    worker = Worker(native_carving[0], native_carving[1])
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    identity = None
    try:
        end = time.monotonic() + 45
        while time.monotonic() < end:
            current = native_carving[0].run(queued_run["id"])
            if current.get("process"):
                identity = current["process"]
                break
            if current["status"] not in {"queued", "running"}:
                break
            time.sleep(0.005)
        assert identity, "Native carver did not enter the managed process step"
        assert process_identity(identity["pid"]) == identity["start_time"]
        native_carving[0].request_cancel(queued_run["id"])
        thread.join(timeout=15)
        assert not thread.is_alive()
        run = native_carving[0].run(queued_run["id"])
        assert run["status"] == "cancelled", run.get("error")
        assert process_identity(identity["pid"]) != identity["start_time"]
        assert all(not f["complete"] for f in native_carving[0].artifacts(run["id"]))
    finally:
        worker.stop.set()
        thread.join(timeout=15)
        source.unlink(missing_ok=True)


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_carved_pdf_enters_hash_verified_derived_examination(native_carving, tool):
    if not shutil.which("pdftotext"):
        pytest.skip("pdftotext is not installed")
    repo, settings, source, outputs, _ = native_carving
    repo.add_case(
        {"id": "case", "name": "Carving case", "slug": "carving", "artifacts": []}
    )
    run, output, _ = execute(native_carving, tool, types=["pdf"], case_id="case")
    assert_verified(native_carving, run, output)
    target = output / recoveries(output)[0]["File"]
    plan, case, record = compile_plan(
        "pdftotext",
        {
            "case_id": "case",
            "source_path": str(target),
            "output_path": str(outputs / "examined pdf"),
        },
        settings,
        repo,
    )
    assert (
        record["source_run_id"] == run["id"]
        and record["baseline_sha256"] == hashlib.sha256(samples()["pdf"]).hexdigest()
    )
    exam = enqueue(repo, plan, record, case)
    Worker(repo, settings).run_once()
    assert repo.run(exam["id"])["status"] == "success"
    assert (
        "Known forensic PDF marker"
        in (Path(plan.output_path) / "pdftotext.txt").read_text()
    )
    repo.add_case({"id": "other", "name": "Other case", "artifacts": []})
    target.chmod(0o644)
    target.write_bytes(b"%PDF-1.4\nchanged derived evidence\n")
    with pytest.raises(ValidationError):
        compile_plan(
            "pdftotext",
            {
                "source_path": str(target),
                "case_id": "other",
                "output_path": str(outputs / "wrong case"),
            },
            settings,
            repo,
        )
    altered, case, record = compile_plan(
        "pdftotext",
        {
            "source_path": str(target),
            "case_id": "case",
            "output_path": str(outputs / "altered"),
        },
        settings,
        repo,
    )
    attempt = enqueue(repo, altered, record, case)
    Worker(repo, settings).run_once()
    failed = repo.run(attempt["id"])
    assert (
        failed["status"] == "error"
        and "baseline" in failed["error"]
        and failed["steps"] == []
    )


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_known_png_at_end_of_image_records_native_recovery_limits(native_carving, tool):
    source = native_carving[2]
    data = samples()["png"]
    source.write_bytes(b"\0" * 512 + data)
    run, output, plan = execute(native_carving, tool, types=["png"])
    assert_verified(native_carving, run, output)
    direct = native_carving[3] / "edge direct"
    workspace = native_carving[3] / "edge workspace"
    workspace.mkdir()
    for name, content in plan.configs.items():
        (workspace / name).write_text(content)
    cli = subprocess.run(
        resolve_argv(plan.steps[0].argv, direct, workspace),
        capture_output=True,
        timeout=30,
    )
    assert cli.returncode == 0
    expected = [p.read_bytes() for p in direct.rglob("*.png")]
    actual = [(output / r["File"]).read_bytes() for r in recoveries(output)]
    assert actual == expected
    if actual:
        assert actual == [data]


@pytest.mark.parametrize("kind", ["doc", "ole"])
def test_public_word_document_native_results_and_audit_are_preserved(
    native_carving, kind
):
    value = os.environ.get("SIFTED_TEST_WORD_DOCUMENT")
    if not value:
        pytest.skip(
            "Set SIFTED_TEST_WORD_DOCUMENT to the documented Apache POI fixture"
        )
    data = Path(value).read_bytes()
    assert (
        hashlib.sha256(data).hexdigest()
        == "4876e828e62d490fa188c7c4e47013e2e0dfdf02f5903dfd374bc0d2b2049ca1"
    )
    source = native_carving[2]
    source.write_bytes(b"\0" * 512 + data + b"\0" * 1024)
    run, output, plan = execute(native_carving, "foremost", types=[kind])
    assert_verified(native_carving, run, output)
    direct = native_carving[3] / "word direct"
    workspace = native_carving[3] / "word workspace"
    workspace.mkdir()
    for name, content in plan.configs.items():
        (workspace / name).write_text(content)
    cli = subprocess.run(
        resolve_argv(plan.steps[0].argv, direct, workspace),
        capture_output=True,
        timeout=30,
    )
    assert cli.returncode == 0
    files = lambda root: sorted(
        (p.relative_to(root).as_posix(), p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
        and p.name != "audit.txt"
        and "_sifted" not in p.parts
        and p.name != "carved.csv"
    )
    assert files(output) == files(direct)
    assert run["file_count"] == parse_carving_audit(direct / "audit.txt")[1]


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_native_timeout_is_applied_to_process_and_partial_output(native_carving, tool):
    source = native_carving[2]
    with source.open("wb") as handle:
        handle.truncate(4 * 1024**3)
    try:
        # Keep hashing under the job budget; impose a one-second subprocess budget.
        repo, settings, _, outputs, _ = native_carving
        if not shutil.which(tool):
            pytest.skip(tool + " is not installed")
        plan, case, record = compile_plan(
            tool,
            {
                "source_path": str(source),
                "output_path": str(outputs / "timeout"),
                "types": ["jpg"],
            },
            settings,
            repo,
        )
        plan.steps[0].timeout = 1
        run = enqueue(repo, plan, record, case)
        Worker(repo, settings).run_once()
        result = repo.run(run["id"])
        assert result["status"] == "error" and "execution timeout" in result["error"], (
            result.get("error")
        )
        assert result["steps"][0]["return_code"] == 124 and all(
            not f["complete"] for f in repo.artifacts(run["id"])
        )
    finally:
        source.unlink(missing_ok=True)


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_selected_scope_excludes_other_formats_in_the_same_image(native_carving, tool):
    source = native_carving[2]
    expected = mixed_image(source, types=("jpg", "png", "pdf", "exe"), duplicate=False)
    run, output, _ = execute(native_carving, tool, types=["jpg"])
    assert_verified(native_carving, run, output)
    rows = recoveries(output)
    assert len(rows) == 1 and rows[0]["Type"] == "jpg"
    assert (output / rows[0]["File"]).read_bytes() == expected[0][2]
