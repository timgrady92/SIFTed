"""Carving contracts: faithful configuration, audited bytes, and honest failures."""

import csv
import hashlib
import sys
from pathlib import Path

import pytest

from app import create_app
from sifted_core.adapters import compile_plan
from sifted_core.carving import scalpel_profiles
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, ValidationError
from sifted_core.viewers import parse_carving_audit
from sifted_core.worker import Worker
from test_runtime import enqueue


@pytest.fixture
def carving_runtime(tmp_path):
    source = tmp_path / 'source with "quotes" and spaces.dd'
    source.write_bytes(b"AknownB")
    script = tmp_path / "carver.py"
    script.write_text("""import sys
from pathlib import Path
tool,scenario,*args=sys.argv[1:]
out=Path(args[args.index('-o')+1]);out.mkdir()
source=args[args.index('-i')+1] if tool=='foremost' else args[-1]
name='00000000.jpg'; data=b'known'; offset=1
if scenario=='wrong_bytes': data=b'wrong'
if scenario=='wrong_offset': offset=0
if scenario!='missing_file':
 (out/'jpg').mkdir();(out/'jpg'/name).write_bytes(data)
if scenario=='extra_file': (out/'unexpected.bin').write_bytes(b'extra')
if scenario=='symlink': (out/'linked.jpg').symlink_to(source)
if scenario=='duplicate_file':
 (out/'other').mkdir();(out/'other'/name).write_bytes(data)
if scenario=='nested_audit':
 (out/'other').mkdir();(out/'other'/'audit.txt').write_text('unreported output')
if tool=='foremost':
 audit=f'Foremost version 1.5.7\\nFile: {source}\\nNum Name (bs=512) Size File Offset Comment\\n0: {name} 5 B {offset} \\nFinish: now\\n1 FILES EXTRACTED\\nForemost finished at now\\n'
else:
 audit=f'Scalpel version 1.60 audit file\\nOpening target "{source}"\\nFile Start Chop Length Extracted From\\n{name} {offset} NO 5 {Path(source).name}\\nCompleted at now\\n'
if scenario=='malformed': audit=audit.replace(name+' ', '../bad '+name+' ',1)
if scenario=='incomplete': audit=audit.replace('Foremost finished at now','').replace('Completed at now','')
if scenario=='wrong_source': audit=audit.replace(source,'another source')
if scenario=='wrong_count': audit=audit.replace('1 FILES EXTRACTED','2 FILES EXTRACTED')
if scenario=='wrong_length': audit=audit.replace('NO 5 ', 'NO 6 ')
if scenario=='duplicate_record':
 row=next(line for line in audit.splitlines() if name in line)
 audit=audit.replace(row,row+'\\n'+row).replace('1 FILES EXTRACTED','2 FILES EXTRACTED')
(out/'audit.txt').write_text(audit)
""")
    settings = Settings(
        input_roots=[str(tmp_path)],
        output_roots=[str(tmp_path)],
        binaries={
            tool: [sys.executable, str(script), tool, "valid"]
            for tool in ("foremost", "scalpel")
        },
        timeout_seconds=5,
    )
    return Repository(tmp_path / "runtime.db"), settings, source, script


def submit(runtime, tool, scenario="valid", **options):
    repo, settings, source, script = runtime
    settings.binaries[tool] = [sys.executable, str(script), tool, scenario]
    plan, case, record = compile_plan(
        tool,
        {
            "source_path": str(source),
            "output_path": str(source.parent / "results"),
            "types": ["jpg"],
            **options,
        },
        settings,
        repo,
    )
    queued = enqueue(repo, plan, record, case)
    Worker(repo, settings).run_once()
    return repo.run(queued["id"]), Path(plan.output_path)


@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_success_requires_audited_exact_bytes_and_offsets(carving_runtime, tool):
    repo, _, source, _ = carving_runtime
    before = source.read_bytes()
    run, output = submit(carving_runtime, tool)
    assert run["status"] == "success", run.get("error")
    assert run["file_count"] == 1 and run["analysis"]["recovered_bytes"] == 5
    with (output / "carved.csv").open() as handle:
        row = next(csv.DictReader(handle))
    assert row["Offset Bytes"] == "1" and row["Length Bytes"] == "5"
    assert row["SHA-256"] == hashlib.sha256(b"known").hexdigest()
    assert source.read_bytes() == before
    assert (output / "_sifted" / (tool + ".conf")).is_file()
    table, count, _ = parse_carving_audit(output / "audit.txt")
    assert table["rows"][0][1] == "1" and count == 1
    for item in repo.artifacts(run["id"]):
        assert (
            item["complete"]
            and hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        )


@pytest.mark.parametrize(
    "tool,scenario,message",
    [
        *(
            (tool, scenario, message)
            for tool in ("foremost", "scalpel")
            for scenario, message in [
                ("wrong_bytes", "bytes disagree"),
                ("wrong_offset", "bytes disagree"),
                ("missing_file", "missing or duplicate"),
                ("extra_file", "absent from its audit"),
                ("nested_audit", "absent from its audit"),
                ("duplicate_file", "ambiguous duplicate"),
                ("duplicate_record", "missing or duplicate"),
                ("symlink", "symbolic links"),
                ("malformed", "Unrecognized"),
                ("incomplete", "completion marker"),
                ("wrong_source", "different source"),
            ]
        ),
        ("foremost", "wrong_count", "count"),
        ("scalpel", "wrong_length", "length"),
    ],
)
def test_zero_exit_is_not_success_when_recovery_contract_is_broken(
    carving_runtime, tool, scenario, message
):
    run, output = submit(carving_runtime, tool, scenario)
    assert run["status"] == "error" and message in run["error"]
    assert (output / "audit.txt").is_file()
    assert carving_runtime[0].artifacts(run["id"])
    assert all(not item["complete"] for item in carving_runtime[0].artifacts(run["id"]))


@pytest.mark.parametrize(
    "tool,options",
    [
        ("foremost", {"types": []}),
        ("scalpel", {"types": []}),
        ("foremost", {"types": ["tif"]}),
        ("scalpel", {"types": ["exe"]}),
    ],
)
def test_unsupported_type_selections_never_enqueue(carving_runtime, tool, options):
    with pytest.raises(ValidationError):
        submit(carving_runtime, tool, **options)
    assert carving_runtime[0].runs() == []


@pytest.mark.parametrize(
    "header,suffix",
    [
        (b"EVF\x09", ".dd"),
        (b"LVF\x09", ".dd"),
        (b"AFF\0", ".aff"),
        (b"QFI\xfb", ".dd"),
        (b"vhdxfile", ".dd"),
        (b"KDMV", ".dd"),
        (b"\x1f\x8b", ".dd"),
        (b"fake", ".E01"),
    ],
)
@pytest.mark.parametrize("tool", ["foremost", "scalpel"])
def test_container_images_cannot_be_misrepresented_as_raw(
    carving_runtime, tool, header, suffix
):
    source = carving_runtime[2]
    if suffix != ".dd":
        source = source.rename(source.with_suffix(suffix))
    source.write_bytes(header + b"\0" * 100)
    repo, settings, _, _ = carving_runtime
    with pytest.raises(ValidationError, match="raw byte stream"):
        compile_plan(
            tool,
            {
                "source_path": str(source),
                "output_path": str(source.parent / "result"),
                "types": ["jpg"],
            },
            settings,
            repo,
        )


def test_split_image_requires_combined_raw_stream(carving_runtime):
    repo, settings, source, _ = carving_runtime
    first = source.with_suffix(".001")
    first.write_bytes(b"first segment")
    first.with_suffix(".002").write_bytes(b"second segment")
    with pytest.raises(ValidationError, match="Combine split"):
        compile_plan(
            "foremost",
            {
                "source_path": str(first),
                "output_path": str(source.parent / "result"),
                "types": ["jpg"],
            },
            settings,
            repo,
        )


def test_scalpel_snapshots_only_active_rules_and_preserves_wildcard_and_direction(
    carving_runtime,
):
    repo, settings, source, _ = carving_runtime
    profile = source.parent / "selected.conf"
    profile.write_text(
        r"wildcard \x40"
        + "\n#jpg y 100 OTHER FOOTER\nabc n 8192 HEAD@ TAIL REVERSE\nabc y 1024 START STOP NEXT\nunused y 42 IGNORE\n"
    )
    settings.scalpel_config = str(profile)
    plan, _, _ = compile_plan(
        "scalpel",
        {
            "source_path": str(source),
            "output_path": str(source.parent / "result"),
            "types": ["abc"],
        },
        settings,
        repo,
    )
    snapshot = plan.configs["scalpel.conf"]
    assert (
        r"wildcard \x40" in snapshot
        and "HEAD@ TAIL REVERSE" in snapshot
        and "START STOP NEXT" in snapshot
    )
    assert "OTHER" not in snapshot and "IGNORE" not in snapshot
    assert (
        hashlib.sha256(snapshot.encode()).hexdigest()
        == plan.parameters["profile_sha256"]
    )
    profile.write_text("abc y 1024 CHANGED\n")
    assert "CHANGED" not in plan.configs["scalpel.conf"]


@pytest.mark.parametrize(
    "rule",
    [
        "#jpg y 10 HEAD END",
        "jpg y -1 HEAD",
        "jpg y 0 HEAD",
        "jpg maybe 10 HEAD",
        "wildcard @@",
        "wildcard @\nwildcard ?",
        "jpg y 10 HEAD\nwildcard @",
        "jpg y 10 HEAD END INVALID",
        "toolongextension y 10 HEAD",
        r"jpg y 10 HEAD\xzz END",
        r"jpg y 10 HEAD\x0 END",
        r"jpg y 10 HEAD\999 END",
        "jpg y 10 HEAD\\",
        "jpg y 10 " + "x" * 4096,
        "jpg y 10",
    ],
)
def test_invalid_or_comment_only_custom_profiles_fail_clearly(tmp_path, rule):
    profile = tmp_path / "invalid.conf"
    profile.write_text(rule)
    with pytest.raises(ValidationError):
        scalpel_profiles(profile)


def test_custom_scalpel_types_are_visible_and_comment_examples_are_not(carving_runtime):
    _, settings, source, _ = carving_runtime
    profile = source.parent / "custom.conf"
    profile.write_text("#bad y 10 H T\ncustom y 10 HEAD TAIL\n")
    app = create_app(
        {
            "TESTING": True,
            "SIFTED_DATABASE_PATH": str(source.parent / "web.db"),
            "SIFTED_INPUT_ROOTS": settings.input_roots,
            "SIFTED_OUTPUT_ROOTS": settings.output_roots,
            "SIFTED_SCALPEL_CONFIG": str(profile),
        }
    )
    response = app.test_client().get("/scalpel")
    assert (
        response.status_code == 200
        and b'value="custom"' in response.data
        and b'value="bad"' not in response.data
    )
    profile.write_text("# no active rules\n")
    response = app.test_client().get("/scalpel")
    assert (
        response.status_code == 200
        and b"no active rules" in response.data
        and b'id="runScalpel" disabled' in response.data
    )


def test_extensionless_scalpel_recovery_requires_flat_output(carving_runtime):
    repo, settings, source, _ = carving_runtime
    profile = source.parent / "extensionless.conf"
    profile.write_text("NONE y 100 HEAD END\n")
    settings.scalpel_config = str(profile)
    data = {
        "source_path": str(source),
        "output_path": str(source.parent / "result"),
        "types": ["NONE"],
    }
    with pytest.raises(ValidationError, match="Disable grouping"):
        compile_plan("scalpel", data, settings, repo)
    assert repo.runs() == []
    plan, _, _ = compile_plan("scalpel", {**data, "organize": False}, settings, repo)
    assert "-O" in plan.steps[0].argv
