"""Execution and HTTP coverage for tools shared with the sibling SIFTed app."""
import csv
import hashlib
from pathlib import Path
import sys
import uuid

import pytest

from app import create_app
from sifted_core.adapters import compile_plan
from sifted_core.catalog import EZ_TOOL_CATALOG
from sifted_core.disk_tools import DISK_TOOL_IDS, image_sources
from sifted_core.examination_tools import EXAMINATION_TOOL_IDS
from sifted_core.storage import Repository
from sifted_core.tool_base import Plan, ValidationError
from sifted_core.worker import Worker


@pytest.fixture
def integrated(tmp_path):
    evidence = tmp_path / "original evidence"
    evidence.mkdir()
    outputs = tmp_path / "derived outputs"
    outputs.mkdir()
    source = evidence / "disk with spaces.img"
    source.write_bytes(b"%PDF-1.7\nsynthetic evidence")
    script = tmp_path / "fake integrations.py"
    script.write_text('''import sys
from pathlib import Path
tool,*args=sys.argv[1:]
if tool == "mmls":
 print("DOS Partition Table\\nOffset Sector: 0\\nUnits are in 512-byte sectors\\n Slot Start End Length Size Description\\n00: Meta 0 0 1 512B Primary Table (#0)\\n01: 000:000 2048 4095 2048 1M Linux (0x83)")
elif tool == "fls":
 print("d/d 5:\\tUsers\\nr/r * 42-128-1:\\tdeleted file with spaces.txt\\nr/r 43-128-1:\\tname <script>.txt")
elif tool == "icat": sys.stdout.buffer.write(b"\\x00\\xff known extracted bytes\\n")
elif tool in {"blkcat", "blkls"}: sys.stdout.buffer.write(b"\\x00\\xff binary data unit")
elif tool == "blkstat": print("Allocation Status: Unallocated")
elif tool == "blkcalc": print("731")
elif tool == "head": print("bounded text sample")
elif tool == "xxd": print("00000000: 00 ff 20 6b 6e 6f 77 6e                          .. known")
elif tool == "pdfinfo": print("Title: Synthetic PDF")
elif tool == "pdftotext": print("Synthetic PDF text")
else: print("Filesystem metadata")
''')
    binaries = {tool: [sys.executable, str(script), tool] for tool in DISK_TOOL_IDS + EXAMINATION_TOOL_IDS}
    app = create_app({"TESTING": True, "SIFTED_DATABASE_PATH": str(tmp_path / "runtime.sqlite3"),
                      "SIFTED_INPUT_ROOTS": [str(evidence)], "SIFTED_OUTPUT_ROOTS": [str(outputs)], "SIFTED_BINARIES": binaries})
    return app, Repository(app.config["DATABASE_PATH"]), app.config["SETTINGS"], source, outputs


def execute(integrated, tool, **options):
    app, repo, settings, source, outputs = integrated
    payload = {"source_path": str(source), "output_path": str(outputs / uuid.uuid4().hex), **options}
    client = app.test_client()
    preview = client.post(f"/api/{tool}/preview", json=payload)
    created = client.post(f"/api/{tool}/run", json=payload)
    assert created.status_code == 202, created.json
    assert preview.json["commands"] == created.json["commands"]
    Worker(repo, settings).run_once()
    run = repo.run(created.json["run_id"])
    assert run["status"] == "success", run.get("error")
    for entry in repo.artifacts(run["id"]):
        assert hashlib.sha256(Path(entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    if run.get("analysis"):
        response = client.get(f"/run/{run['id']}/analysis")
        assert response.status_code == 200, response.data
    return run


@pytest.mark.parametrize("tool,options", [
    ("mmls", {}), ("fsstat", {"offset_sector": 2048, "sector_size": 4096}),
    ("fls", {"offset_sector": 2048, "recursive": True}), ("istat", {"metadata_address": "42-128-1"}),
    ("icat", {"metadata_address": "42-128-1", "entry_name": "extracted content.bin", "recover_deleted": True}),
    ("blkstat", {"block_address": 2}), ("blkcat", {"block_address": 2}), ("blkls", {"block_address": 2, "end_block": 3}),
    ("blkcalc", {"block_address": 2}), ("head", {}), ("xxd", {"byte_offset": 10}), ("pdfinfo", {}), ("pdftotext", {})])
def test_new_tools_have_identical_preview_and_execution_and_hashed_outputs(integrated, tool, options):
    run = execute(integrated, tool, **options)
    output = Path(run["output_path"])
    if tool == "istat":
        assert run["steps"][0]["argv"][-1] == "42"
    if tool == "icat":
        assert run["steps"][0]["argv"][-1] == "42-128-1"
        assert (output / "extracted content.bin").read_bytes() == b"\x00\xff known extracted bytes\n"
    if tool == "fls":
        with (output / "fls.csv").open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert rows[1]["Metadata Address"] == "42-128-1" and rows[1]["Deleted"] == "Yes"
        assert rows[2]["Name"] == "name <script>.txt"
        page = integrated[0].test_client().get(f"/run/{run['id']}/analysis")
        assert b"name &lt;script&gt;.txt" in page.data and b"/workflow/icat?" in page.data
    if tool == "mmls":
        assert run["analysis"]["sector_size"] == 512
        with (output / "mmls.csv").open(newline="") as handle:
            assert list(csv.DictReader(handle))[1]["Start Sector"] == "2048"


@pytest.mark.parametrize("tool,options", [
    ("fsstat", {"offset_sector": -1}), ("fsstat", {"offset_sector": True}), ("fsstat", {"offset_sector": 2**53}),
    ("mmls", {"sector_size": 513}), ("fls", {"recursive": "false"}), ("fls", {"directory_inode": "42;whoami"}),
    ("istat", {"metadata_address": "--help"}), ("icat", {"metadata_address": "42", "entry_name": "../outside"}),
    ("icat", {"metadata_address": "42", "entry_name": "..\\outside"}), ("blkcat", {"block_address": -1}),
    ("blkls", {"block_address": 10, "end_block": 9}), ("blkls", {"block_address": 1, "end_block": 1025}),
    ("blkcalc", {"block_address": 1, "direction": []}), ("head", {"byte_limit": 65537}),
    ("xxd", {"byte_offset": 0.1}), ("pdftotext", {"first_page": 5, "last_page": 4})])
def test_invalid_requests_cannot_create_jobs(integrated, tool, options):
    app, repo, _, source, outputs = integrated
    response = app.test_client().post(f"/api/{tool}/run", json={"source_path": str(source), "output_path": str(outputs / "out"), **options})
    assert response.status_code == 400
    assert not repo.runs()


def test_pdf_validation_uses_content_not_filename(integrated):
    _, repo, settings, source, outputs = integrated
    source.write_bytes(b"not a PDF")
    source = source.rename(source.with_suffix(".pdf"))
    with pytest.raises(ValidationError, match="PDF header"):
        compile_plan("pdfinfo", {"source_path": str(source), "output_path": str(outputs / "out")}, settings, repo)


def test_derived_inputs_keep_producer_and_hash_with_separate_input_roots(integrated):
    app, repo, settings, _, outputs = integrated
    repo.add_case({"id": "case", "name": "Case", "slug": "case", "artifacts": []})
    extracted = execute(integrated, "icat", case_id="case", metadata_address="42", entry_name="derived.bin")
    source = str(Path(extracted["output_path"]) / "derived.bin")
    run = execute(integrated, "xxd", case_id="case", source_path=source)
    record = repo.input(run["id"])
    assert record["source_run_id"] == extracted["id"]
    assert record["baseline_sha256"] == hashlib.sha256(Path(source).read_bytes()).hexdigest()
    inputs = app.test_client().get("/api/case/case/inputs").json["inputs"]
    assert any(item["path"] == source and item["source_run_id"] == extracted["id"] for item in inputs)
    with pytest.raises(ValidationError, match="outside allowed input"):
        compile_plan("xxd", {"source_path": source, "output_path": str(outputs / "wrong-case")}, settings, repo)
    Path(source).write_bytes(b"changed derived bytes")
    created = app.test_client().post("/api/xxd/run", json={"case_id": "case", "source_path": source, "output_path": str(outputs / "mutated")})
    Worker(repo, settings).run_once()
    failed = repo.run(created.json["run_id"])
    assert failed["status"] == "error" and "SHA-256" in failed["error"]


def test_segment_mutation_and_membership_changes_fail_before_tools_run(integrated):
    app, repo, settings, source, outputs = integrated
    first = source.with_name("segmented.001")
    second = source.with_name("segmented.002")
    first.write_bytes(b"first"); second.write_bytes(b"second")
    created = app.test_client().post("/api/fls/run", json={"source_path": str(first), "output_path": str(outputs / "split")})
    assert created.status_code == 202
    plan = Plan.from_dict(repo.run(created.json["run_id"])["plan"])
    assert plan.input_paths == [str(first), str(second)]
    second.write_bytes(b"changed")
    Worker(repo, settings).run_once()
    assert "Image segment changed" in repo.run(created.json["run_id"])["error"]
    source.with_name("segmented.004").write_bytes(b"gap")
    with pytest.raises(ValidationError, match="gap"):
        image_sources(str(first))


def test_bounded_binary_sample_fails_without_claiming_complete_output(integrated):
    app, repo, settings, source, outputs = integrated
    settings.binaries["blkcat"] = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'Z' * (2*1024*1024))"]
    response = app.test_client().post("/api/blkcat/run", json={"source_path": str(source), "output_path": str(outputs / "large"), "block_address": 0})
    Worker(repo, settings).run_once()
    run = repo.run(response.json["run_id"])
    assert run["status"] == "error" and "bounded output" in run["error"]
    assert (outputs / "large/blkcat.bin").stat().st_size == 1024*1024
    assert all(not entry["complete"] for entry in repo.artifacts(run["id"]))


def test_context_geometry_cannot_be_changed_between_follow_up_actions(integrated):
    _, repo, settings, source, outputs = integrated
    run = execute(integrated, "fls", offset_sector=2048)
    with pytest.raises(ValidationError, match="geometry"):
        compile_plan("istat", {"source_path": str(source), "output_path": str(outputs / "out"),
                              "context_run_id": run["id"], "offset_sector": 0, "metadata_address": "42"}, settings, repo)


def test_context_hash_survives_source_changes_before_follow_up_is_queued(integrated):
    app, repo, settings, source, outputs = integrated
    context = execute(integrated, "fls", offset_sector=2048)
    source.write_bytes(b"different image at the same path")
    response = app.test_client().post("/api/istat/run", json={"source_path": str(source), "output_path": str(outputs / "stale-context"),
                            "context_run_id": context["id"], "offset_sector": 2048, "metadata_address": "42"})
    Worker(repo, settings).run_once()
    run = repo.run(response.json["run_id"])
    assert run["status"] == "error" and "SHA-256" in run["error"]


def test_original_block_mapping_is_verified_independently_of_reported_index(integrated):
    _, _, settings, _, _ = integrated
    settings.binaries["blkls"] = [sys.executable, "-c", "print('addr|alloc\\n54|f\\n90|f\\n101|f')"]
    run = execute(integrated, "blkcalc", direction="original_to_unallocated", block_address=101)
    assert run["analysis"]["reported_address"] == "731"
    assert run["analysis"]["mapped_address"] == "2"
    assert len(run["steps"]) == 2


@pytest.mark.parametrize("tool_id", list(EZ_TOOL_CATALOG))
def test_existing_zimmerman_tools_have_complete_export_contracts(integrated, tmp_path, tool_id):
    _, _, settings, source, _ = integrated
    tool = EZ_TOOL_CATALOG[tool_id]
    script = tmp_path / "fake parser.py"
    script.write_text('''import sys
from pathlib import Path
tool,*args=sys.argv[1:]
output=Path(args[args.index("--csv")+1]); output.mkdir(parents=True)
filename=args[args.index("--csvf")+1] if "--csvf" in args else "mapped.csv"
data="EventId,RecordNumber\\n4624,1\\n" if tool=="evtxecmd" else "FileName,EntryNumber\\n$MFT,0\\n" if tool=="mftecmd" else "Name,Value\\nKnown,1\\n"
(output/filename).write_text(data)
''')
    settings.binaries[tool_id] = [sys.executable, str(script), tool_id]
    settings.ez_root = str(tmp_path / "EZ root")
    batch = Path(settings.ez_root) / "RECmd/BatchExamples/RegistryASEPs.reb"
    batch.parent.mkdir(parents=True)
    batch.write_text("Description: Synthetic registry batch\n")
    if tool_id == "evtxecmd":
        source.write_bytes(b"ElfFile\x00synthetic EVTX")
    elif tool_id == "mftecmd":
        source.write_bytes(b"FILEsynthetic MFT")
    source = source.parent if tool["input_mode"] == "dir" else source
    run = execute(integrated, "eric-zimmerman", tool_id=tool_id, source_path=str(source))
    assert run["analysis"]["entry_count"] == 1
    if tool.get("batch_file"):
        assert (Path(run["output_path"]) / "_sifted/registry-batch.reb").read_text() == batch.read_text()


@pytest.mark.parametrize("tool_id", ["evtxecmd", "mftecmd"])
def test_windows_parser_source_signature_is_required(integrated, tool_id):
    app, repo, _, source, outputs = integrated
    response = app.test_client().post("/api/eric-zimmerman/run", json={"tool_id": tool_id, "source_path": str(source), "output_path": str(outputs / "invalid")})
    assert response.status_code == 400 and "signature" in response.json["error"]
    assert not repo.runs()


def test_parser_cannot_claim_success_with_malformed_csv(integrated, tmp_path):
    app, repo, settings, source, outputs = integrated
    source.write_bytes(b"FILEsynthetic MFT")
    script = tmp_path / "bad csv.py"
    script.write_text('import sys\nfrom pathlib import Path\na=sys.argv\np=Path(a[a.index("--csv")+1]);p.mkdir();(p/"mft.csv").write_text("FileName,EntryNumber\\nmalformed,0,extra\\n")\n')
    settings.binaries["mftecmd"] = [sys.executable, str(script)]
    created = app.test_client().post("/api/eric-zimmerman/run", json={"tool_id": "mftecmd", "source_path": str(source), "output_path": str(outputs / "bad-csv")})
    Worker(repo, settings).run_once()
    failed = repo.run(created.json["run_id"])
    assert failed["status"] == "error" and "column count" in failed["error"]
    assert all(not entry["complete"] for entry in repo.artifacts(failed["id"]))
