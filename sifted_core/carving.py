"""Native carving plans, explicit signature profiles, and verified recovery ranges."""

import csv
import hashlib
import re
from pathlib import Path

from .disk_tools import image_sources
from .tool_base import (
    OUTPUT,
    WORKSPACE,
    Plan,
    Step,
    ToolAdapter,
    ValidationError,
    choices,
    executable,
    flag,
)

# Native Foremost 1.5.7 selectors, verified on SIFT. RIFF uses 'rif'; no TIFF parser.
FOREMOST_TYPES = (
    "jpg",
    "png",
    "gif",
    "bmp",
    "pdf",
    "doc",
    "ole",
    "zip",
    "rar",
    "exe",
    "avi",
    "mpg",
    "wav",
    "rif",
    "wmv",
    "mov",
    "htm",
    "cpp",
)
DEFAULT_PROFILES = str(Path(__file__).with_name("carving_profiles.conf"))
FOREMOST_CONFIG = (
    "# SIFTed: selected Foremost built-in parsers only; no custom signatures.\n"
)
COLUMNS = [
    "File",
    "Type",
    "Offset Bytes",
    "Length Bytes",
    "SHA-256",
    "Chopped",
    "Comment",
]
NAME = r"[A-Za-z0-9_.-]+"
FOREMOST_ROW = re.compile(
    r"^\s*\d+:\s+(" + NAME + r")\s+(\d+(?:\.\d+)?\s+[KMGT]?B)\s+(\d+)\s*(.*)$"
)
SCALPEL_ROW = re.compile(r"^(" + NAME + r")\s+(\d+)\s+(YES|NO)\s+(\d+)\s+(.+)$")


SIGNATURE_TOKEN = re.compile(r"\\(?:[\\asnrtv]|x[0-9a-fA-F]{2}|[0-3][0-7]{2})|[^\\]")


def signature_size(value):
    """Validate native escapes before Scalpel's C decoder sees the signature."""
    position = size = 0
    for match in SIGNATURE_TOKEN.finditer(value):
        if match.start() != position:
            return None
        token = match.group()
        size += 1 if token.startswith("\\") else len(token.encode("utf-8"))
        position = match.end()
    return size if position == len(value) else None


def scalpel_profiles(path):
    """Read active rules only. Never enable commented examples or alter signatures."""
    try:
        data = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"Tool configuration is unavailable: {path}") from exc
    rules, directives = {}, []
    for number, line in enumerate(data.splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        fields = value.split()
        if (
            fields[0] == "wildcard"
            and len(fields) == 2
            and signature_size(fields[1]) == 1
        ):
            if directives or rules:
                raise ValidationError(
                    "Scalpel wildcard must be declared once, before all active rules."
                )
            directives.append(value)
            continue
        if (
            not 4 <= len(fields) <= 6
            or not re.fullmatch(r"[a-zA-Z0-9_]{1,7}", fields[0])
            or fields[1] not in {"y", "n"}
            or not fields[2].isdigit()
            or not 0 < int(fields[2]) < 2**63
            or any(
                len(f.encode("utf-8")) > 4095 or not signature_size(f)
                for f in fields[3:5]
            )
            or (len(fields) == 6 and fields[5] not in {"FORWARD", "REVERSE", "NEXT"})
        ):
            raise ValidationError(
                f"Invalid Scalpel 1.60 rule at line {number} in {path}."
            )
        rules.setdefault(fields[0], []).append(value)
    if sum(len(values) for values in rules.values()) >= 100:
        raise ValidationError(
            "Scalpel 1.60 profiles must contain fewer than 100 active rules."
        )
    if not rules:
        raise ValidationError(
            "Scalpel configuration has no active rules. Select a profile with enabled signatures."
        )
    return rules, directives


def available_types(tool, settings):
    return (
        list(FOREMOST_TYPES)
        if tool == "foremost"
        else list(scalpel_profiles(settings.scalpel_config)[0])
    )


def validate_raw_source(source):
    if source == "<source_path>":
        return
    if any(c in source for c in "\r\n\t"):
        raise ValidationError(
            "Carving source paths must not contain tabs or newlines; native audits cannot represent them."
        )
    try:
        with open(source, "rb") as handle:
            header = handle.read(16)
    except OSError as exc:
        raise ValidationError(
            "Unable to inspect the carving source: " + str(exc)
        ) from exc
    if header.startswith(
        (b"EVF", b"LVF", b"AFF\x00", b"QFI\xfb", b"vhdxfile", b"KDMV", b"\x1f\x8b")
    ) or Path(source).suffix.casefold() in {
        ".e01",
        ".ex01",
        ".l01",
        ".lx01",
        ".aff",
        ".aff4",
        ".vmdk",
        ".vhd",
        ".vhdx",
        ".qcow",
        ".qcow2",
    }:
        raise ValidationError(
            "Carving requires a raw byte stream. Export or decompress this image container to raw first; carving the container does not scan its decoded evidence."
        )
    if len(image_sources(source)) > 1:
        raise ValidationError(
            "Carving requires a complete raw byte stream. Combine split image segments before carving."
        )


class CarvingAdapter(ToolAdapter):
    def __init__(self, tool_id):
        self.tool_id = tool_id
        self.parameter_names = (
            {"types", "organize"}
            if tool_id == "scalpel"
            else {"types", "quick", "verbose"}
        )

    def build(self, p, source, output, settings, preview=False):
        validate_raw_source(source)
        rules, directives = (
            scalpel_profiles(settings.scalpel_config)
            if self.tool_id == "scalpel"
            else ({}, [])
        )
        types = choices(p, "types", rules if rules else FOREMOST_TYPES)
        if not types:
            raise ValidationError("Select at least one file type.")
        prefix = executable(self.tool_id, [self.tool_id], settings, not preview)
        name = self.tool_id + ".conf"
        if self.tool_id == "foremost":
            config = FOREMOST_CONFIG
            args = prefix + [
                "-c",
                WORKSPACE + "/" + name,
                "-t",
                ",".join(types),
                "-i",
                source,
                "-o",
                OUTPUT,
            ]
            quick, verbose = flag(p, "quick"), flag(p, "verbose")
            args += (["-q"] if quick else []) + (["-v"] if verbose else [])
            parameters = {
                "types": types,
                "quick": quick,
                "verbose": verbose,
                "recovery_method": "built-in parsers",
            }
        else:
            config = (
                "# SIFTed selected active Scalpel rules\n"
                + "\n".join(directives + [r for t in types for r in rules[t]])
                + "\n"
            )
            args = prefix + ["-c", WORKSPACE + "/" + name, "-o", OUTPUT]
            organize = flag(p, "organize", True)
            if organize and any(t.upper().startswith("NONE") for t in types):
                raise ValidationError(
                    "Scalpel cannot group extensionless NONE rules into valid UTF-8 directories. "
                    "Disable grouping for extensionless recovery."
                )
            args += ([] if organize else ["-O"]) + [source]
            parameters = {
                "types": types,
                "organize": organize,
                "recovery_method": "header/footer signatures",
                "profile_path": str(Path(settings.scalpel_config).resolve()),
            }
        parameters["profile_sha256"] = hashlib.sha256(config.encode()).hexdigest()
        return Plan(
            self.tool_id,
            source,
            output,
            [Step(args, "Carve files", timeout=settings.timeout_seconds)],
            configs={name: config},
            parameters=parameters,
            expected_files=["audit.txt"],
            postprocess="carving",
        )

    def validate_execution(self, plan, settings):
        validate_raw_source(plan.source)


def audit_entries(path, tool, check=lambda: None, expected_source=None):
    """Stream native records; require a complete single-source audit even with zero hits."""
    header = table = finished = False
    count = sources = 0
    declared = None
    in_table = False
    with Path(path).open(encoding="utf-8", errors="strict") as handle:
        while True:
            check()
            line = handle.readline(256 * 1024 + 1)
            if not line:
                break
            if len(line) > 256 * 1024:
                raise ValueError("Carving audit line exceeds the supported limit.")
            value = line.strip()
            source_prefix = "File: " if tool == "foremost" else 'Opening target "'
            if line.startswith(source_prefix):
                sources += 1
                named_source = line.rstrip("\r\n")[len(source_prefix) :]
                if tool == "scalpel":
                    named_source = named_source.removesuffix('"')
                if expected_source is not None and named_source != expected_source:
                    raise ValueError(
                        "Carving audit references a different source image."
                    )
            if value.startswith(
                ("Foremost version " if tool == "foremost" else "Scalpel version ")
            ):
                header = True
            if (
                tool == "foremost"
                and value.startswith("Num")
                and "File Offset" in value
                or tool == "scalpel"
                and value.startswith("File")
                and "Extracted From" in value
            ):
                if table:
                    raise ValueError("Carving audit contains multiple source tables.")
                table = in_table = True
                continue
            if tool == "foremost":
                if value.startswith("Finish:"):
                    in_table = False
                if value.startswith("Foremost finished at "):
                    finished = True
                total = re.fullmatch(r"(\d+) FILES EXTRACTED", value)
                if total:
                    declared = int(total[1])
                match = (
                    FOREMOST_ROW.fullmatch(line.rstrip("\r\n")) if in_table else None
                )
                if match:
                    name, displayed_size, offset, comment = match.groups()
                    record = {
                        "name": name,
                        "offset": int(offset),
                        "length": None,
                        "chopped": "not reported",
                        "comment": comment,
                        "audit_size": displayed_size,
                    }
            else:
                if value.startswith("Completed at "):
                    finished = True
                    in_table = False
                match = SCALPEL_ROW.fullmatch(line.rstrip("\r\n")) if in_table else None
                if match:
                    name, offset, chopped, length, source_name = match.groups()
                    record = {
                        "name": name,
                        "offset": int(offset),
                        "length": int(length),
                        "chopped": chopped,
                        "comment": "",
                        "source_name": source_name,
                    }
            if match:
                count += 1
                yield record
            elif in_table and value:
                raise ValueError("Unrecognized carving audit record: " + value[:200])
    if not (header and table and finished and sources == 1):
        raise ValueError(
            "Carving audit is missing its header, recovery table, or completion marker."
        )
    if tool == "foremost" and declared != count:
        raise ValueError("Foremost recovery count does not match its audit records.")


def verify_recoveries(plan, output, check):
    """Validate tool output against its audit and source; publish bounded CSV evidence."""
    indexed = {}
    for path in output.rglob("*"):
        check()
        if path.is_symlink():
            raise ValueError("Carving output must not contain symbolic links.")
        if not path.is_file() and not path.is_dir():
            raise ValueError(
                "Carving output must contain regular files and directories only."
            )
        if path.is_file() and path != output / "audit.txt":
            if path.name in indexed:
                raise ValueError(
                    "Carving output has ambiguous duplicate filenames: " + path.name
                )
            indexed[path.name] = path
    seen = set()
    count = total_bytes = chopped = 0
    source_size = Path(plan.source).stat().st_size
    with (
        open(plan.source, "rb") as evidence,
        (output / "carved.csv").open("x", encoding="utf-8", newline="") as target,
    ):
        writer = csv.writer(target)
        writer.writerow(COLUMNS)
        for row in audit_entries(output / "audit.txt", plan.tool, check, plan.source):
            name = row["name"]
            if name not in indexed or name in seen:
                raise ValueError(
                    "Carving audit references a missing or duplicate file: " + name
                )
            path = indexed[name]
            seen.add(name)
            size = path.stat().st_size
            offset = row["offset"]
            if (
                size < 1
                or offset + size > source_size
                or row["length"] is not None
                and size != row["length"]
            ):
                raise ValueError(
                    "Carved file length disagrees with its audit or source range: "
                    + name
                )
            if row.get("source_name", Path(plan.source).name) != Path(plan.source).name:
                raise ValueError("Carving audit references a different source: " + name)
            digest = hashlib.sha256()
            evidence.seek(offset)
            with path.open("rb") as recovered:
                while data := recovered.read(1024 * 1024):
                    check()
                    if data != evidence.read(len(data)):
                        raise ValueError(
                            "Carved bytes disagree with the audited source range: "
                            + name
                        )
                    digest.update(data)
            extension = path.suffix.lstrip(".")
            writer.writerow(
                [
                    path.relative_to(output).as_posix(),
                    extension,
                    offset,
                    size,
                    digest.hexdigest(),
                    row["chopped"],
                    row["comment"],
                ]
            )
            count += 1
            total_bytes += size
            chopped += row["chopped"] == "YES"
        if seen != indexed.keys():
            raise ValueError(
                "Carving output contains files absent from its audit: "
                + ", ".join(sorted(indexed.keys() - seen)[:5])
            )
    return {
        "file_count": count,
        "analysis": {
            "table": "carved.csv",
            "entry_count": count,
            "recovered_bytes": total_bytes,
            "chopped_count": chopped,
            "address_space": "source_byte_stream",
            "recovery_method": plan.parameters["recovery_method"],
            "quick": plan.parameters.get("quick", False),
        },
    }
