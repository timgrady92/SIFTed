"""Parser-specific Zimmerman contracts using verified native assemblies and snapshots."""

import csv
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

from .catalog import EZ_TOOL_CATALOG
from .sqlite_maps import ENGINE_VERSION, available_maps
from .zimmerman_exports import STEMS, process_native_exports
from .tool_base import (
    OUTPUT,
    WORKSPACE,
    Plan,
    Step,
    ToolAdapter,
    ValidationError,
    executable,
    flag,
    signature,
    text,
)


REGISTRY = {"amcacheparser", "appcompatcacheparser", "sbecmd", "recmd"}
FIELDS = {
    "ignore_transaction_logs": {
        "label": "Ignore registry transaction logs",
        "type": "checkbox",
        "default": False,
        "help": "Allows dirty hives without replay. Uncommitted evidence may be missing.",
    },
    "include_program_files": {
        "label": "Include files associated with programs",
        "type": "checkbox",
        "default": True,
    },
    "include_unlisted": {
        "label": "Include automatic-list entries absent from DestList",
        "type": "checkbox",
        "default": False,
    },
    "recover_deleted": {
        "label": "Recover deleted registry keys and values",
        "type": "checkbox",
        "default": False,
    },
    "deduplicate": {
        "label": "Deduplicate identical input files",
        "type": "checkbox",
        "default": False,
    },
}
OPTIONS = {tool: [] for tool in EZ_TOOL_CATALOG}
for _tool in REGISTRY:
    OPTIONS[_tool].append("ignore_transaction_logs")
OPTIONS["amcacheparser"].append("include_program_files")
OPTIONS["jlecmd"].append("include_unlisted")
OPTIONS["recmd"] += ["batch", "recover_deleted"]
OPTIONS["sqlecmd"].append("deduplicate")
OPTIONS["sqlecmd"].append("maps")
SWITCHES = {
    "ignore_transaction_logs": "--nl",
    "include_program_files": "-i",
    "include_unlisted": "--withDir",
    "recover_deleted": "--recover",
}


def native_prefix(tool_id, settings):
    """Use the actual .NET assembly; installed shell wrappers are not execution paths."""
    if tool_id in settings.binaries:
        return executable(tool_id, [], settings)
    dotnet = shutil.which("dotnet")
    name = EZ_TOOL_CATALOG[tool_id]["label"] + ".dll"
    matches = sorted(
        p
        for p in Path(settings.ez_root).rglob(name)
        if p.is_file() and not p.is_symlink()
    )
    if not dotnet or not matches:
        raise ValidationError(
            f"{name} and a working dotnet runtime are required beneath SIFTED_EZ_ROOT."
        )
    if len(matches) != 1:
        raise ValidationError(
            f"Multiple {name} installations found; configure one explicit executable prefix."
        )
    return [dotnet, str(matches[0].resolve())]


def installation_files(prefix, tool_id):
    files = [Path(arg).resolve() for arg in prefix if Path(arg).is_file()]
    assembly = next((path for path in files if path.suffix == ".dll"), None)
    if assembly:
        files += [
            p
            for suffix in (".runtimeconfig.json", ".deps.json")
            if (p := assembly.with_suffix(suffix)).is_file()
        ]
        if tool_id == "recmd":
            files += sorted((assembly.parent / "Plugins").rglob("*.dll"))
    return files


@lru_cache(maxsize=32)
def _probe(prefix, identities):
    environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        result = subprocess.run(
            [*prefix, "-h"], capture_output=True, timeout=20, env=environment
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValidationError(
            "Unable to inspect the installed parser command interface: " + str(exc)
        ) from exc
    data = result.stdout + result.stderr
    if result.returncode or len(data) > 128 * 1024:
        raise ValidationError(
            "Installed parser did not provide a supported command interface."
        )
    value = data.decode("utf-8", errors="strict")
    version = re.search(r"version\s+(\S+)", value, re.I)
    if not version:
        raise ValidationError("Installed parser did not identify its version.")
    options = set(re.findall(r"^\s+(-{1,2}[A-Za-z][\w]*)\b", value, re.M))
    hashes = {
        path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for path, _ in identities
    }
    return {"version": version[1], "options": options, "sha256": hashes}


def probe(prefix, tool_id):
    files = installation_files(prefix, tool_id)
    identities = tuple((str(p), tuple(signature(p))) for p in files)
    return _probe(tuple(prefix), identities)


def required_options(tool_id):
    options = {"-d" if tool_id == "sbecmd" else "-f", "--csv", "--csvf"}
    options.update(SWITCHES[name] for name in OPTIONS[tool_id] if name in SWITCHES)
    if tool_id != "recentfilecacheparser":
        options.update({"--debug", "--dt"})
    if tool_id == "jlecmd":
        options.add("-q")
    if tool_id == "recmd":
        options.update({"--bn", "--dedupe"})
    if tool_id == "evtxecmd":
        options.update({"--maps", "--dedupe"})
    return options


def resource_root(prefix, tool_id, settings):
    assembly = next((Path(arg) for arg in prefix if arg.endswith(".dll")), None)
    if assembly:
        return assembly.parent
    subdir = {"evtxecmd": "EvtxeCmd", "sqlecmd": "SQLECmd", "recmd": "RECmd"}.get(
        tool_id, ""
    )
    return Path(settings.ez_root) / subdir


def batches(root):
    return sorted(
        p.stem
        for p in (root / "BatchExamples").glob("*.reb")
        if p.is_file() and not p.is_symlink()
    )


def configuration(tool_id, prefix, settings, batch="RegistryASEPs"):
    root = resource_root(prefix, tool_id, settings)
    if tool_id == "recmd":
        if batch not in batches(root):
            raise ValidationError("Select an installed RECmd batch profile.")
        files = [(root / "BatchExamples" / (batch + ".reb"), "registry-batch.reb")]
    elif tool_id == "evtxecmd":
        directory = root / "Maps"
        suffix = ".map"
        files = [
            (p, "maps/" + p.relative_to(directory).as_posix())
            for p in sorted(directory.rglob("*"))
            if p.suffix == suffix
        ]
        if not files:
            raise ValidationError(
                "Installed parser maps are unavailable: " + str(directory)
            )
    else:
        files = []
    result = {}
    for path, relative in files:
        if (
            path.is_symlink()
            or not path.is_file()
            or any(parent.is_symlink() for parent in path.parents)
        ):
            raise ValidationError(
                "Parser configuration must contain regular files without symbolic links."
            )
        try:
            value = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            raise ValidationError(
                "Unable to snapshot parser configuration: " + str(path)
            ) from exc
        if len(value.encode()) > 4 * 1024 * 1024 or not value.strip():
            raise ValidationError(
                "Parser configuration is empty or exceeds the supported size: "
                + str(path)
            )
        result[relative] = value
    return result


def resolve_ez_tool(tool_id, settings):
    tool = EZ_TOOL_CATALOG.get(tool_id)
    if not tool:
        return None
    result = {
        **tool,
        "id": tool_id,
        "installed": False,
        "binary_display": "",
        "version": None,
        "options": [
            {"name": name, **FIELDS[name]}
            for name in OPTIONS[tool_id]
            if name in FIELDS
        ],
        "export_summary": "One or more validated CSV exports with native parser-defined suffixes.",
    }
    try:
        if tool_id == "sqlecmd":
            profiles, rejected = available_maps(Path(settings.ez_root) / "SQLECmd/Maps")
            if not profiles:
                raise ValidationError(
                    "No valid SQLECmd maps are installed beneath SIFTED_EZ_ROOT."
                )
            result.update(
                installed=True,
                version="SIFTed executor " + ENGINE_VERSION,
                error=None,
                binary_display="SIFTed SQLite maps",
                export_summary="Streamed CSV exports, extracted blobs and per-query outcomes; SQLite localtime resolves to UTC.",
            )
            result["options"].insert(
                0,
                {
                    "name": "maps",
                    "label": "SQLite maps (optional explicit selection)",
                    "type": "multiselect",
                    "choices": list(profiles),
                    "default": [],
                    "help": "With no selection, maps are chosen by the original database filename. Select profiles explicitly for renamed databases.",
                },
            )
            result["rejected_maps"] = rejected
            return result
        prefix = native_prefix(tool_id, settings)
        capability = probe(prefix, tool_id)
        missing = required_options(tool_id) - capability["options"]
        if missing:
            raise ValidationError(
                "Installed parser lacks required options: " + ", ".join(sorted(missing))
            )
        configuration(tool_id, prefix, settings)
        result.update(
            installed=True,
            binary_display=shlex.join(prefix),
            version=capability["version"],
            error=None,
        )
        if tool_id == "recmd":
            result["options"].insert(
                0,
                {
                    "name": "batch",
                    "label": "Registry batch profile",
                    "type": "select",
                    "choices": batches(resource_root(prefix, tool_id, settings)),
                    "default": "RegistryASEPs",
                },
            )
    except (ValidationError, OSError, UnicodeError) as exc:
        result["error"] = str(exc)
    return result


def matches_file(tool_id, path):
    name = path.name.casefold()
    if tool_id == "lecmd":
        return name.endswith(".lnk")
    if tool_id == "jlecmd":
        return name.endswith((".automaticdestinations-ms", ".customdestinations-ms"))
    if tool_id == "evtxecmd":
        return name.endswith(".evtx")
    if tool_id == "rbcmd":
        return name.startswith("$i") or name == "info2"
    if tool_id in REGISTRY:
        if re.search(r"\.log.$", name):
            return False
        with path.open("rb") as handle:
            header = handle.read(512)
        if not header.startswith(b"regf"):
            return False
        if tool_id == "sbecmd":
            identity = (
                name
                + " "
                + header[48:112].decode("utf-16-le", errors="ignore").casefold()
            )
            return "ntuser" in identity or "usrclass" in identity
        return True
    if tool_id == "sqlecmd":
        with path.open("rb") as handle:
            return handle.read(16) == b"SQLite format 3\0"
    return False


def validate_file(tool_id, path):
    with path.open("rb") as handle:
        header = handle.read(512)
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - 4))
        footer = handle.read(4)
    valid = {
        "evtxecmd": header.startswith(b"ElfFile\0")
        and size >= 4096
        and struct.unpack_from("<IHHH", header, 32) == (128, 1, 3, 4096)
        and size >= 4096 + struct.unpack_from("<H", header, 42)[0] * 65536,
        "mftecmd": header.startswith(b"FILE"),
        "lecmd": header.startswith(
            bytes.fromhex("4c0000000114020000000000c000000000000046")
        )
        and len(header) >= 76,
        "jlecmd": header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        or size > 24
        and footer == b"\xab\xfb\xbf\xba",
        "recentfilecacheparser": header.startswith(b"\xfe\xff\xee\xff")
        and len(header) >= 20,
        "rbcmd": header[:8] in (struct.pack("<Q", 1), struct.pack("<Q", 2))
        or path.name.casefold() == "info2"
        and header[:4] in (struct.pack("<I", 4), struct.pack("<I", 5)),
        "sqlecmd": header.startswith(b"SQLite format 3\0"),
    }.get(tool_id, header.startswith(b"regf") and len(header) >= 512)
    if not valid:
        raise ValidationError(
            f"{EZ_TOOL_CATALOG[tool_id]['label']} source has an incompatible file signature: {path.name}"
        )
    return header


def input_contract(tool_id, source, ignore_logs=False):
    path = Path(source)
    if source == "<source_path>":
        return [], {}, []
    selected = (
        [path]
        if path.is_file()
        else sorted(
            p for p in path.rglob("*") if p.is_file() and matches_file(tool_id, p)
        )
    )
    if not selected:
        raise ValidationError(
            "The selected directory contains no compatible parser inputs."
        )
    copies, related = {}, []
    for index, item in enumerate(selected):
        if item.is_symlink():
            raise ValidationError("Parser inputs must not contain symbolic links.")
        header = validate_file(tool_id, item)
        if path.is_file() and tool_id not in REGISTRY and tool_id != "sqlecmd":
            continue
        destination = (
            f"input/{index:04d}/" + item.name if path.is_dir() else "input/" + item.name
        )
        copies[str(item)] = destination
        sidecars = []
        for candidate in item.parent.iterdir():
            suffix = (
                candidate.name[len(item.name) :]
                if candidate.name[: len(item.name)].casefold() == item.name.casefold()
                else ""
            )
            if (
                tool_id in REGISTRY
                and not ignore_logs
                and re.fullmatch(r"\.LOG.", suffix, re.I)
            ):
                target = destination + suffix.upper()
            elif tool_id == "sqlecmd" and suffix in {"-wal", "-shm", "-journal"}:
                target = destination + suffix
            else:
                continue
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or target in copies.values()
            ):
                raise ValidationError(
                    "Parser sidecar is non-regular or ambiguous: " + str(candidate)
                )
            if tool_id in REGISTRY:
                with candidate.open("rb") as handle:
                    log_header = handle.read(4)
                if candidate.stat().st_size < 512 or log_header not in {
                    b"regf",
                    b"HvLE",
                }:
                    raise ValidationError(
                        "Registry transaction log is empty or has an incompatible signature: "
                        + str(candidate)
                    )
            copies[str(candidate)] = target
            sidecars.append(candidate)
            if path.is_file():
                related.append(str(candidate))
        if (
            tool_id in REGISTRY
            and header[4:8] != header[8:12]
            and not ignore_logs
            and not sidecars
        ):
            raise ValidationError(
                "Dirty registry hive requires its transaction logs. Supply the logs or explicitly choose to ignore them: "
                + item.name
            )
    return [str(p) for p in selected], copies, related


def build_sqlite_maps(p, source, output, settings):
    invalid = p.keys() - {
        "tool_id",
        "source_path",
        "output_path",
        "case_id",
        "maps",
        "deduplicate",
    }
    if invalid:
        raise ValidationError(
            "Unsupported SQLite map options: " + ", ".join(sorted(invalid))
        )
    profiles, rejected = available_maps(Path(settings.ez_root) / "SQLECmd/Maps")
    if not profiles:
        raise ValidationError(
            "No valid SQLECmd maps are installed beneath SIFTED_EZ_ROOT."
        )
    chosen = p.get("maps", [])
    if not isinstance(chosen, list) or any(
        not isinstance(name, str) or name not in profiles for name in chosen
    ):
        raise ValidationError("Select valid installed SQLite map names.")
    selected, copies, related = input_contract("sqlecmd", source)
    tasks = []
    used = set()
    for path in selected:
        names = (
            list(dict.fromkeys(chosen))
            if chosen
            else [
                name
                for name, profile in profiles.items()
                if profile["map"]["FileName"].casefold() == Path(path).name.casefold()
            ]
        )
        if not names:
            raise ValidationError(
                "No SQLite map matches "
                + Path(path).name
                + "; select a profile explicitly."
            )
        used.update(names)
        working = copies[path]
        tasks.append(
            {
                "source": path,
                "working_path": working,
                "maps": names,
                "has_sidecars": any(
                    name.startswith(working + "-") for name in copies.values()
                ),
            }
        )
    if (
        not selected
    ):  # A preview without evidence still renders a concrete engine command.
        used.update(chosen)
    configs = {"maps/" + name: profiles[name]["content"] for name in sorted(used)}
    request = {
        "inputs": tasks,
        "maps": {name: "maps/" + name for name in sorted(used)},
        "deduplicate": flag(p, "deduplicate"),
        "query_seconds": min(settings.timeout_seconds, 90),
    }
    configs["sqlite-request.json"] = json.dumps(request, indent=2)
    prefix = [sys.executable, str(Path(__file__).with_name("sqlite_maps.py"))]
    capability = probe(prefix, "sqlecmd")
    parameters = {
        "parser_id": "sqlecmd",
        "version": "SIFTed executor " + ENGINE_VERSION,
        "engine": "SIFTed SQLite maps",
        "timezone": "UTC",
        "selected_inputs": selected,
        "maps": sorted(used),
        "rejected_maps": rejected,
        "deduplicate": request["deduplicate"],
        "installation_sha256": capability["sha256"],
    }
    parameters["configuration_sha256"] = hashlib.sha256(
        json.dumps(configs, sort_keys=True).encode()
    ).hexdigest()
    return Plan(
        "eric-zimmerman",
        source,
        output,
        [
            Step(
                [
                    *prefix,
                    "--request",
                    WORKSPACE + "/sqlite-request.json",
                    "--output",
                    OUTPUT,
                ],
                "SQLite maps",
                OUTPUT + "/parser-log.txt",
                settings.timeout_seconds,
            )
        ],
        configs=configs,
        parameters=parameters,
        input_copies=copies,
        auxiliary_paths=related,
        create_output_directory=True,
        postprocess="zimmerman",
        postprocess_on_failure=True,
    )


def process_sqlite_maps(plan, output, check):
    with (output / "map-summary.json").open(encoding="utf-8") as handle:
        summary = json.load(handle)
    if summary.get("engine") != "SIFTed SQLite maps" or not isinstance(
        summary.get("queries"), list
    ):
        raise ValueError("SQLite map executor did not produce valid query outcomes.")
    tables = []
    errors = list(summary["errors"])
    seen = set()
    for record in summary["queries"]:
        check()
        if record["status"] != "success":
            continue
        name = record["file"]
        if Path(name).name != name or name in seen:
            raise ValueError(
                "SQLite executor reported an invalid or duplicate export path."
            )
        seen.add(name)
        path = output / name
        if path.is_symlink():
            raise ValueError("SQLite executor output must not be a symbolic link.")
        with path.open(newline="", encoding="utf-8", errors="strict") as handle:
            reader = csv.reader(handle, strict=True)
            columns = next(reader)
            if (
                not columns
                or len(set(columns)) != len(columns)
                or "SourceFile" not in columns
            ):
                raise ValueError("SQLite export has an invalid header.")
            count = 0
            for row in reader:
                check()
                if len(row) != len(columns) or row[-1] != record["source"]:
                    raise ValueError(
                        "SQLite export has an invalid source or column count."
                    )
                count += 1
        if count != record["entry_count"]:
            raise ValueError("SQLite export count disagrees with its query summary.")
        tables.append({"file": name, "entry_count": count})
    return {
        "validation_errors": errors,
        "analysis": {
            "table": tables[0]["file"] if tables else None,
            "tables": tables,
            "csv_count": len(tables),
            "entry_count": sum(t["entry_count"] for t in tables),
            "parser_id": "sqlecmd",
            "parser_version": plan.parameters["version"],
            "engine": summary["engine"],
            "sqlite_version": summary["sqlite_version"],
            "timezone": "UTC",
            "query_outcomes": summary["queries"],
            "capture_outcomes": summary["captures"],
            "staged_inputs": True,
        },
    }


class ZimmermanAdapter(ToolAdapter):
    tool_id = "eric-zimmerman"
    source_kind = "file_or_dir"
    parameter_names = {"tool_id", *FIELDS, "batch", "maps"}

    def build(self, p, source, output, settings, preview=False):
        tool_id = text(p, "tool_id")
        tool = EZ_TOOL_CATALOG.get(tool_id)
        if not tool:
            raise ValidationError("Select a supported Zimmerman parser.")
        if tool_id == "sqlecmd":
            return build_sqlite_maps(p, source, output, settings)
        invalid = p.keys() - {
            "tool_id",
            "source_path",
            "output_path",
            "case_id",
            *OPTIONS[tool_id],
        }
        if invalid:
            raise ValidationError(
                "Unsupported options for this parser: " + ", ".join(sorted(invalid))
            )
        is_dir = Path(source).is_dir()
        if source != "<source_path>" and (
            tool["input_mode"] == "file"
            and is_dir
            or tool["input_mode"] == "dir"
            and not is_dir
        ):
            raise ValidationError(
                "Source type does not match this parser's accepted input."
            )
        values = {
            name: flag(p, name, FIELDS[name]["default"])
            for name in OPTIONS[tool_id]
            if name != "batch"
        }
        selected, copies, related = input_contract(
            tool_id, source, values.get("ignore_transaction_logs", False)
        )
        prefix = native_prefix(tool_id, settings)
        capability = probe(prefix, tool_id)
        batch = text(p, "batch", "RegistryASEPs")
        configs = configuration(tool_id, prefix, settings, batch)
        options = ["--csvf", STEMS[tool_id] + ".csv"]
        if tool_id != "recentfilecacheparser":
            options += ["--debug", "--dt", "yyyy-MM-dd HH:mm:ss.fffffff"]
        if tool_id == "jlecmd":
            # Native custom-list verbose reporting labels its source path ERR.
            # Quiet mode removes this presentation-only message; debug diagnostics
            # and actual parse failures remain visible and validated.
            options.append("-q")
        for name, value in values.items():
            if value:
                options.append(SWITCHES[name])
        if tool_id in {"recmd", "evtxecmd"}:
            options += ["--dedupe", "false"]
        if tool_id == "recmd":
            options += ["--bn", WORKSPACE + "/registry-batch.reb"]
        if tool_id == "evtxecmd":
            options += ["--maps", WORKSPACE + "/maps"]
        steps, scopes = [], []
        for index, path in enumerate(selected or [source]):
            native_source = WORKSPACE + "/" + copies[path] if path in copies else path
            if tool_id == "sbecmd":
                native_source = native_source.rsplit("/", 1)[0]
            scope = f"inputs/{index:04d}" if is_dir else ""
            target = OUTPUT + "/" + scope if scope else OUTPUT
            args = [
                *prefix,
                "-d" if tool_id == "sbecmd" else "-f",
                native_source,
                "--csv",
                target,
                *options,
            ]
            steps.append(
                Step(
                    args,
                    tool["label"] + (f" / input {index:04d}" if is_dir else ""),
                    target + "/parser-log.txt",
                    settings.timeout_seconds,
                    continue_on_error=True,
                    stderr=target + "/parser-stderr.txt",
                )
            )
            scopes.append(scope)
        required = {
            arg
            for step in steps
            for arg in step.argv[len(prefix) :]
            if arg.startswith("-")
        }
        if not required.issubset(capability["options"]):
            raise ValidationError(
                "Installed parser lacks required options: "
                + ", ".join(sorted(required - capability["options"]))
            )
        parameters = {
            "parser_id": tool_id,
            "version": capability["version"],
            "installation_sha256": capability["sha256"],
            "selected_inputs": selected,
            "input_copies": copies,
            "export_scopes": scopes,
            **values,
        }
        if tool_id == "recmd":
            parameters["batch"] = batch
        parameters["configuration_sha256"] = hashlib.sha256(
            json.dumps(configs, sort_keys=True).encode()
        ).hexdigest()
        return Plan(
            self.tool_id,
            source,
            output,
            steps,
            configs=configs,
            parameters=parameters,
            input_copies=copies,
            auxiliary_paths=related,
            postprocess="zimmerman",
            postprocess_on_failure=True,
            create_output_directory=True,
        )

    def validate_execution(self, plan, settings):
        tool_id = plan.parameters["parser_id"]
        if tool_id == "sqlecmd":
            prefix = [sys.executable, str(Path(__file__).with_name("sqlite_maps.py"))]
            current = probe(prefix, tool_id)
            if current["sha256"] != plan.parameters["installation_sha256"]:
                raise ValidationError(
                    "SQLite map executor changed while queued; submit a new run."
                )
            selected, copies, _ = input_contract(tool_id, plan.source)
            if (
                selected != plan.parameters["selected_inputs"]
                or copies != plan.input_copies
            ):
                raise ValidationError(
                    "SQLite input or sidecar membership changed while queued."
                )
            return
        prefix = native_prefix(tool_id, settings)
        current = probe(prefix, tool_id)
        if current["sha256"] != plan.parameters["installation_sha256"]:
            raise ValidationError(
                "Parser installation changed while queued; submit a new run."
            )
        selected, copies, _ = input_contract(
            tool_id, plan.source, plan.parameters.get("ignore_transaction_logs", False)
        )
        if (
            selected != plan.parameters["selected_inputs"]
            or copies != plan.input_copies
        ):
            raise ValidationError(
                "Parser input or sidecar membership changed while queued."
            )


def process_exports(plan, output, check):
    if plan.parameters["parser_id"] == "sqlecmd":
        return process_sqlite_maps(plan, output, check)
    return process_native_exports(
        {**plan.parameters, "input_copies": plan.input_copies}, output, check
    )
