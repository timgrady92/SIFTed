"""Real installed-tool checks through the same adapters and worker as the UI."""
import csv
import hashlib
import json
import shutil
import uuid
from pathlib import Path

import pytest

from sifted_core.adapters import Settings, ValidationError, compile_plan
from sifted_core.storage import Repository, utc_now
from sifted_core.worker import Worker


@pytest.fixture
def installed_runtime(tmp_path):
    evidence = tmp_path / "evidence with spaces"
    evidence.mkdir()
    sample = evidence / "sample with spaces.jpg"
    shutil.copyfile(Path(__file__).parent / "samples/images/geotagged.jpg", sample)
    outputs = tmp_path / "outputs with spaces"
    outputs.mkdir()
    return Repository(tmp_path / "runtime.db"), Settings(input_roots=[str(evidence)], output_roots=[str(outputs)], timeout_seconds=120), sample, outputs


def execute(runtime, tool, source=None, **options):
    repo, settings, sample, outputs = runtime
    source = source or sample
    data = {"source_path": str(source), "output_path": str(outputs / uuid.uuid4().hex), **options}
    try:
        plan, case, record = compile_plan(tool, data, settings, repo)
    except ValidationError as exc:
        if "not installed" in str(exc) or "configuration is unavailable" in str(exc):
            pytest.skip(str(exc))
        raise
    run_id = uuid.uuid4().hex
    run = {"id": run_id, "tool": plan.tool, "case_id": case, "status": "queued", "created_at": utc_now(),
           "output_path": plan.output_path, "log_path": plan.output_path + ".log", "plan": plan.to_dict()}
    repo.enqueue(run, record)
    Worker(repo, settings).run_once()
    result = repo.run(run_id)
    assert result["status"] == "success", result.get("error")
    files = repo.artifacts(run_id)
    assert files
    for item in files:
        assert item["sha256"] == hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
    assert result["executables"]
    return Path(plan.output_path), result


@pytest.mark.live
def test_installed_strings(installed_runtime):
    sample = installed_runtime[2]
    sample.write_bytes(b"known_ascii_marker\0" + "unicode_marker".encode("utf-16-le"))
    output, _ = execute(installed_runtime, "strings")
    assert "known_ascii_marker" in (output / "strings.txt").read_text()
    output, _ = execute(installed_runtime, "strings", encoding="l")
    assert "unicode_marker" in (output / "strings.txt").read_text()


@pytest.mark.live
@pytest.mark.parametrize("fmt", ["csv", "json"])
def test_installed_exiftool(installed_runtime, fmt):
    output, _ = execute(installed_runtime, "exiftool", output_format=fmt)
    if fmt == "csv":
        with open(output / "metadata.csv", newline="") as handle:
            row = next(csv.DictReader(handle))
    else:
        row = json.loads((output / "metadata.json").read_text())[0]
    assert any("JPEG" == value for value in row.values())
    assert any("TestCamera" == value for value in row.values())


@pytest.mark.live
def test_installed_filetype_reports_mime_mismatch(installed_runtime):
    source = installed_runtime[2].with_suffix(".png")
    shutil.copyfile(installed_runtime[2], source)
    output, run = execute(installed_runtime, "filetype", source=source, mismatch_only=True)
    with open(output / "filetypes.csv", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["Detected Type"] == "image/jpeg" and row["Mismatch"] == "Yes"
    assert run["mismatch_count"] == 1


@pytest.mark.live
@pytest.mark.parametrize("tool,options", [("foremost", {}), ("foremost", {"safe_mode": True}), ("scalpel", {})])
def test_installed_carvers_preserve_recovered_jpeg(installed_runtime, tool, options):
    output, _ = execute(installed_runtime, tool, types=["jpg"], **options)
    assert list(output.rglob("*.jpg"))
    assert list(output.rglob("audit.txt"))


@pytest.mark.live
def test_installed_bulk_extractor(installed_runtime):
    source = installed_runtime[2]
    source.write_bytes(b"known.user@example.com\nhttps://example.com/known-forensic-marker\n" * 1000)
    output, _ = execute(installed_runtime, "bulk-extractor", focus_scanners=["email"])
    assert "known.user@example.com" in (output / "email.txt").read_text()


@pytest.mark.live
def test_installed_plaso(installed_runtime):
    source = installed_runtime[2].with_suffix(".log")
    source.write_text("Jan  1 00:00:01 test-host test-service: known-forensic-marker\n")
    output, _ = execute(installed_runtime, "artifact-triage", source=source)
    assert (output / "timeline.plaso").stat().st_size > 0
    assert "known-forensic-marker" in (output / "timeline.csv").read_text()


@pytest.mark.live
def test_installed_lecmd_parses_synthetic_unicode_link(installed_runtime):
    import struct
    target = "known forensic target.txt"
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 76)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<II", header, 20, 0x88, 0x80)  # Relative path and Unicode StringData.
    struct.pack_into("<I", header, 60, 1)
    source = installed_runtime[2].with_suffix(".lnk")
    source.write_bytes(header + struct.pack("<H", len(target)) + target.encode("utf-16-le"))
    output, run = execute(installed_runtime, "eric-zimmerman", source=source, tool_id="lecmd")
    assert target in (output / "lnk.csv").read_text()
    assert any(path.endswith("LECmd.dll") for path in run["executables"])
