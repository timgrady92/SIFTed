"""All nine Sleuth Kit tools on a known synthetic filesystem, through the worker."""
import csv
import shutil
import subprocess

import pytest

from test_live_tools import execute
from tool_fixtures import make_disk, make_pdf
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings


@pytest.fixture
def disk_runtime(tmp_path):
    if not all(shutil.which(tool) for tool in ("mmls", "fls", "icat", "fsstat", "istat", "blkstat", "blkcat", "blkls", "blkcalc")):
        pytest.skip("The Sleuth Kit is not installed.")
    evidence = tmp_path / "evidence with spaces"
    evidence.mkdir()
    outputs = tmp_path / "outputs with spaces"
    outputs.mkdir()
    disk = make_disk(evidence)
    settings = Settings(input_roots=[str(evidence)], output_roots=[str(outputs)], timeout_seconds=120)
    return (Repository(tmp_path / "state.sqlite3"), settings, disk["path"], outputs), disk


@pytest.mark.live
def test_installed_disk_workflow_and_binary_extraction(disk_runtime):
    runtime, disk = disk_runtime
    output, run = execute(runtime, "mmls")
    with (output / "mmls.csv").open(newline="") as handle:
        entries = list(csv.DictReader(handle))
    partition = next(row for row in entries if row["Kind"] == "allocated")
    assert int(partition["Start Sector"]) == disk["offset"]
    assert run["analysis"]["sector_size"] == 512
    options = {"offset_sector": disk["offset"]}
    output, _ = execute(runtime, "fsstat", **options)
    assert "Ext4" in (output / "fsstat.txt").read_text()
    output, _ = execute(runtime, "fls", recursive=True, **options)
    with (output / "fls.csv").open(newline="") as handle:
        listing = list(csv.DictReader(handle))
    known = next(row for row in listing if row["Name"] == "known.bin")
    assert known["Metadata Address"] == disk["inode"]
    assert any(row["Name"] == "nested/known.pdf" for row in listing)
    output, _ = execute(runtime, "istat", metadata_address=disk["inode"], **options)
    assert "Allocated" in (output / "istat.txt").read_text()
    output, _ = execute(runtime, "icat", metadata_address=disk["inode"], entry_name="extracted known.bin", **options)
    assert (output / "extracted known.bin").read_bytes() == disk["payload"]
    pdf = next(row for row in listing if row["Name"] == "nested/known.pdf")
    output, _ = execute(runtime, "icat", metadata_address=pdf["Metadata Address"], entry_name="derived.pdf", **options)
    assert (output / "derived.pdf").read_bytes().startswith(b"%PDF-")


@pytest.mark.live
def test_installed_block_coordinates_allocation_and_mapping(disk_runtime):
    runtime, disk = disk_runtime
    options = {"offset_sector": disk["offset"]}
    _, run = execute(runtime, "blkstat", block_address=disk["block"], **options)
    assert run["analysis"]["allocation_state"] == "allocated"
    _, run = execute(runtime, "blkstat", block_address=disk["free_block"], **options)
    assert run["analysis"]["allocation_state"] == "unallocated"
    output, _ = execute(runtime, "blkcat", block_address=disk["block"], **options)
    assert (output / "blkcat.bin").read_bytes().startswith(disk["payload"])
    output, _ = execute(runtime, "blkls", block_address=disk["free_block"], **options)
    assert (output / "blkls.bin").stat().st_size == 1024
    output, _ = execute(runtime, "blkls", block_address=disk["block"], **options)
    assert (output / "blkls.bin").stat().st_size == 0
    _, run = execute(runtime, "blkcalc", block_address=0, direction="unallocated_to_original", **options)
    mapped = int(run["analysis"]["mapped_address"])
    _, reverse = execute(runtime, "blkcalc", block_address=mapped, direction="original_to_unallocated", **options)
    assert reverse["analysis"]["mapped_address"] == "0"


@pytest.mark.live
def test_installed_geometry_uses_configured_4096_byte_sectors(tmp_path):
    if not shutil.which("mmls") or not shutil.which("fls"):
        pytest.skip("The Sleuth Kit is not installed.")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    disk = make_disk(evidence, sector_size=4096)
    runtime = (Repository(tmp_path / "state.sqlite3"), Settings(input_roots=[str(evidence)], output_roots=[str(outputs)], timeout_seconds=120), disk["path"], outputs)
    _, run = execute(runtime, "mmls", sector_size=4096)
    assert run["analysis"]["sector_size"] == 4096
    output, _ = execute(runtime, "fls", sector_size=4096, offset_sector=disk["offset"])
    assert "known.bin" in (output / "fls.csv").read_text()


@pytest.mark.live
def test_installed_text_hex_and_pdf_examination(tmp_path):
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    source = tmp_path / "known text.bin"
    source.write_bytes(b"known_text_marker\n" * 10000)
    runtime = (Repository(tmp_path / "state.sqlite3"), Settings(input_roots=[str(tmp_path)], output_roots=[str(outputs)], timeout_seconds=120), source, outputs)
    output, _ = execute(runtime, "head", byte_limit=1024)
    assert (output / "head.txt").read_bytes() == source.read_bytes()[:1024]
    output, _ = execute(runtime, "xxd", byte_offset=5, byte_limit=16)
    assert (output / "xxd.txt").read_text().startswith("00000005:")
    pdf = make_pdf(tmp_path / "PDF content with misleading extension.bin")
    output, _ = execute(runtime, "pdfinfo", source=pdf)
    assert "Pages:" in (output / "pdfinfo.txt").read_text()
    output, _ = execute(runtime, "pdftotext", source=pdf)
    assert "Known forensic PDF marker" in (output / "pdftotext.txt").read_text()


@pytest.mark.live
def test_installed_mftecmd_on_extracted_synthetic_ntfs_metadata(tmp_path):
    mkfs = shutil.which("mkfs.ntfs")
    if not mkfs or not shutil.which("icat"):
        pytest.skip("Synthetic NTFS fixtures require mkfs.ntfs and icat.")
    evidence = tmp_path / "NTFS evidence"
    evidence.mkdir()
    outputs = tmp_path / "parsed outputs"
    outputs.mkdir()
    source = evidence / "synthetic NTFS.img"
    with source.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    subprocess.run([mkfs, "-Q", "-F", str(source)], check=True, capture_output=True)
    runtime = (Repository(tmp_path / "state.sqlite3"), Settings(input_roots=[str(evidence)], output_roots=[str(outputs)], timeout_seconds=120), source, outputs)
    output, producer = execute(runtime, "icat", metadata_address="0", entry_name="$MFT")
    extracted = output / "$MFT"
    assert extracted.read_bytes().startswith(b"FILE")
    parsed, run = execute(runtime, "eric-zimmerman", source=extracted, tool_id="mftecmd")
    with (parsed / "mft.csv").open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert any(row.get("FileName") == "$MFT" for row in rows)
    assert runtime[0].input(run["id"])["source_run_id"] == producer["id"]
