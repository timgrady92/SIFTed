"""Validated, serializable execution plans. Preview and execution share argv.

Only these adapters can create plans; HTTP clients cannot supply command text.
OUTPUT and WORKSPACE tokens are resolved by the worker inside its managed attempt.
"""
import json
import os
import re
import shlex
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .catalog import EZ_TOOL_CATALOG

OUTPUT = "{output}"
WORKSPACE = "{workspace}"


class ValidationError(ValueError):
    pass


def normalize(path):
    return str(Path(path).expanduser().resolve())


def allowed(path, roots):
    target = Path(normalize(path))
    return any(target == Path(root) or Path(root) in target.parents for root in roots)


def signature(path):
    info = os.stat(path)
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def directory_members(path):
    """Snapshot membership and identities, without following evidence symlinks."""
    root = Path(path)
    members = []
    def fail(error):
        raise error

    for folder, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        for name in sorted(dirs + files):
            item = Path(folder) / name
            if item.is_symlink():
                raise ValidationError("Directory evidence must not contain symbolic links: " + str(item))
            if not item.is_file() and not item.is_dir():
                raise ValidationError("Directory evidence must contain regular files and directories only.")
            members.append({"path": item.relative_to(root).as_posix(), "kind": "file" if item.is_file() else "directory",
                            "signature": signature(item)})
    return sorted(members, key=lambda item: item["path"])


@dataclass
class Settings:
    input_roots: list = field(default_factory=lambda: ["/cases"])
    output_roots: list = field(default_factory=lambda: ["/cases"])
    symbol_roots: list = field(default_factory=list)
    plugin_path: str = "data/volatility_plugins.json"
    foremost_config: str = "/etc/foremost.conf"
    scalpel_config: str = "/etc/scalpel/scalpel.conf"
    ez_root: str = "/opt/zimmermantools"
    binaries: dict = field(default_factory=dict)
    timeout_seconds: int = 14400
    max_output_bytes: int = 10 * 1024 ** 3

    def __post_init__(self):
        self.input_roots = [normalize(p) for p in self.input_roots]
        self.output_roots = [normalize(p) for p in self.output_roots]
        self.symbol_roots = [normalize(p) for p in self.symbol_roots]
        if not self.input_roots or not self.output_roots:
            raise ValidationError("Input and output roots must be explicitly configured.")
        if self.timeout_seconds < 1 or self.max_output_bytes < 1:
            raise ValidationError("Execution timeout and output budget must be positive.")


@dataclass
class Step:
    argv: list[str]
    label: str
    stdout: str | None = None
    timeout: int = 14400
    continue_on_error: bool = False


@dataclass
class Plan:
    tool: str
    source: str
    output_path: str
    steps: list[Step] = field(default_factory=list)
    configs: dict = field(default_factory=dict)
    parameters: dict = field(default_factory=dict)
    operation: str = "commands"
    max_output_bytes: int = 10 * 1024 ** 3
    expected_files: list = field(default_factory=list)
    expected_globs: list = field(default_factory=list)
    create_output_directory: bool = False

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        return cls(**{**value, "steps": [Step(**step) for step in value["steps"]]})

    def commands(self, output="<staging_output>", workspace="<job_workspace>"):
        rendered = []
        for step in self.steps:
            command = shlex.join(resolve_argv(step.argv, output, workspace))
            if step.stdout:
                command += " > " + shlex.quote(resolve_token(step.stdout, output, workspace))
            rendered.append(command)
        return rendered


def resolve_token(value, output, workspace):
    for token, path in ((OUTPUT, output), (WORKSPACE, workspace)):
        if value == token or value.startswith(token + "/"):
            return path + value[len(token):]
    return value


def resolve_argv(argv, output, workspace):
    return [resolve_token(arg, str(output), str(workspace)) for arg in argv]


def executable(tool_id, candidates, settings, required=True):
    configured = settings.binaries.get(tool_id)
    if configured:
        prefix = configured if isinstance(configured, list) else [configured]
        if not prefix or any(not isinstance(arg, str) or not arg for arg in prefix):
            raise ValidationError(f"Invalid executable configuration for {tool_id}.")
        path = shutil.which(prefix[0])
        if path:
            return [path, *prefix[1:]]
        if not required:
            return prefix
    elif tool_id in EZ_TOOL_CATALOG:
        # SIFT's shell wrappers use ${*}, losing argument boundaries. Invoke
        # dotnet directly whenever its installed assembly can be discovered.
        dotnet = shutil.which("dotnet")
        root = Path(settings.ez_root)
        if dotnet and root.is_dir():
            dll = next((p for p in root.rglob("*.dll") if p.stem.casefold() == candidates[0].casefold()), None)
            if dll:
                return [dotnet, str(dll.resolve())]
    if not configured:
        for candidate in candidates:
            path = shutil.which(candidate)
            if path:
                return [path]
    if required:
        raise ValidationError(f"{candidates[0]} is not installed or its configured executable is unavailable.")
    return [candidates[0]]


def resolve_ez_tool(tool_id, settings):
    tool = EZ_TOOL_CATALOG.get(tool_id)
    if not tool:
        return None
    prefix = executable(tool_id, tool["binaries"], settings, required=False)
    installed = bool(shutil.which(prefix[0]))
    return {**tool, "id": tool_id, "installed": installed,
            "binary": prefix[0] if installed else None,
            "binary_display": shlex.join(prefix), "argv_prefix": prefix}


def text(payload, key, default=""):
    value = payload.get(key, default)
    if not isinstance(value, str):
        raise ValidationError(f"{key} must be text.")
    return value.strip()


def flag(payload, key, default=False):
    value = payload.get(key, default)
    if not isinstance(value, bool):
        raise ValidationError(f"{key} must be true or false.")
    return value


def choices(payload, key, accepted):
    values = payload.get(key, [])
    if not isinstance(values, list) or any(not isinstance(v, str) or v not in accepted for v in values):
        raise ValidationError(f"Unsupported {key}; choose values from the supported catalog.")
    return list(dict.fromkeys(values))


def config_for_types(path, types):
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        raise ValidationError(f"Tool configuration is unavailable: {path}") from exc
    entries = {}
    for line in lines:
        match = re.match(r"^\s*#?\s*([a-z0-9]+)\s+[yn]\s+\d+", line, re.I)
        if match:
            entries.setdefault(match[1].lower(), []).append(line.lstrip().lstrip("#").strip())
    missing = set(types) - entries.keys()
    if missing:
        raise ValidationError("Types absent from installed configuration: " + ", ".join(sorted(missing)))
    return "# SIFTed configuration snapshot\n" + "\n".join(line for t in types for line in entries[t]) + "\n"


class ToolAdapter:
    """Each adapter owns supported parameters and a persisted execution plan."""

    tool_id = ""
    source_kind = "file"
    parameter_names = frozenset()

    def build(self, payload, source, output, settings, preview=False):
        raise NotImplementedError


class StringsAdapter(ToolAdapter):
    tool_id = "strings"
    parameter_names = {"encoding", "min_length", "show_offsets"}

    def build(self, p, source, output, s, preview=False):
        encoding = text(p, "encoding", "s")
        if encoding not in {"s", "S", "l"}:
            raise ValidationError("Unsupported strings encoding.")
        length = p.get("min_length", 4)
        if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= 100:
            raise ValidationError("Minimum string length must be an integer from 1 to 100.")
        args = executable(self.tool_id, ["strings"], s, not preview) + ["-a", "-e", encoding, "-n", str(length)]
        if flag(p, "show_offsets", True):
            args += ["-t", "x"]
        args += ["--", source]
        return Plan(self.tool_id, source, output, [Step(args, "Extract strings", OUTPUT + "/strings.txt", s.timeout_seconds)], expected_files=["strings.txt"])


class ExifToolAdapter(ToolAdapter):
    tool_id = "exiftool"
    parameter_names = {"output_format", "recursive", "extract_unknown", "duplicates"}
    source_kind = "file_or_dir"

    def build(self, p, source, output, s, preview=False):
        fmt = text(p, "output_format", "csv")
        if fmt not in {"csv", "json"}:
            raise ValidationError("Output format must be csv or json.")
        args = executable(self.tool_id, ["exiftool"], s, not preview) + ["-" + fmt]
        for key, option, default in (("recursive", "-r", True), ("extract_unknown", "-u", False), ("duplicates", "-a", False)):
            if flag(p, key, default):
                args.append(option)
        args += ["-G1", "-s", source]
        return Plan(self.tool_id, source, output, [Step(args, "Extract metadata", OUTPUT + "/metadata." + fmt, s.timeout_seconds)], expected_files=["metadata." + fmt])


class CarvingAdapter(ToolAdapter):
    def __init__(self, tool_id):
        self.tool_id = tool_id
        self.parameter_names = {"types", "organize"} if tool_id == "scalpel" else {"types", "safe_mode", "quick", "verbose"}

    def build(self, p, source, output, s, preview=False):
        types = choices(p, "types", {"jpg", "jpeg", "png", "pdf", "doc", "zip", "exe", "gif", "tif", "tiff", "bmp"})
        types = list(dict.fromkeys({"jpeg": "jpg", "tiff": "tif"}.get(t, t) for t in types))
        prefix = executable(self.tool_id, [self.tool_id], s, not preview)
        plan = Plan(self.tool_id, source, output)
        if self.tool_id == "scalpel":
            if not types:
                raise ValidationError("Select at least one file type.")
            plan.configs["scalpel.conf"] = config_for_types(s.scalpel_config, types)
            args = prefix + ["-c", WORKSPACE + "/scalpel.conf", "-o", OUTPUT]
            if not flag(p, "organize", True):
                args.append("-O")
            plan.steps = [Step(args + [source], "Carve files", timeout=s.timeout_seconds)]
        else:
            safe = flag(p, "safe_mode")
            if safe and not types:
                raise ValidationError("Select at least one type for safe mode.")
            extra = (["-q"] if flag(p, "quick") else []) + (["-v"] if flag(p, "verbose") else [])
            # Each safe-mode type has its own output/audit directory, preserving
            # every occurrence and allowing partial results to remain explicit.
            groups = [[t] for t in types] if safe else [types]
            for i, group in enumerate(groups):
                args = prefix + ["-i", source, "-o", OUTPUT + ("/" + group[0] if safe else "")]
                if group:
                    name = f"foremost-{i}.conf"
                    plan.configs[name] = config_for_types(s.foremost_config, group)
                    args += ["-t", ",".join(group), "-c", WORKSPACE + "/" + name]
                plan.steps.append(Step(args + extra, "Carve " + (",".join(group) or "default types"),
                                       timeout=10 if safe else s.timeout_seconds, continue_on_error=safe))
        plan.parameters = {"types": types}
        return plan


class BulkAdapter(ToolAdapter):
    tool_id = "bulk-extractor"
    parameter_names = {"focus_scanners", "advanced_scanners", "info_mode", "histograms"}

    def build(self, p, source, output, s, preview=False):
        focus = choices(p, "focus_scanners", {"email", "accts", "httplogs", "exif", "pdf", "zip", "winlnk", "winprefetch"})
        advanced = choices(p, "advanced_scanners", {"wordlist", "facebook", "outlook", "xor"})
        args = executable(self.tool_id, ["bulk_extractor"], s, not preview) + ["-o", OUTPUT]
        if flag(p, "info_mode"):
            args.append("-i")
        if not flag(p, "histograms", True):
            args += ["-S", "enable_histograms=NO"]
        if focus:
            args += ["-x", "all"]
        for scanner in focus + advanced:
            args += ["-e", scanner]
        return Plan(self.tool_id, source, output, [Step(args + [source], "Extract features", timeout=s.timeout_seconds)])


class ZimmermanAdapter(ToolAdapter):
    tool_id = "eric-zimmerman"
    parameter_names = {"tool_id"}
    source_kind = "file_or_dir"

    def build(self, p, source, output, s, preview=False):
        tool_id = text(p, "tool_id")
        tool = EZ_TOOL_CATALOG.get(tool_id)
        if not tool:
            raise ValidationError("Unknown Eric Zimmerman tool.")
        is_dir = Path(source).is_dir()
        if source != "<source_path>" and ((tool["input_mode"] == "dir" and not is_dir) or (tool["input_mode"] == "file" and is_dir)):
            raise ValidationError("Source type does not match this parser's accepted input.")
        args = executable(tool_id, tool["binaries"], s, not preview) + ["-d" if is_dir or tool["input_mode"] == "dir" else "-f", source, "--csv", OUTPUT]
        configs = {}
        if tool.get("batch_file"):
            batch = Path(s.ez_root) / "RECmd/BatchExamples/RegistryASEPs.reb"
            if not preview and not batch.is_file():
                raise ValidationError("RECmd batch configuration is unavailable.")
            if batch.is_file():
                configs["registry-batch.reb"] = batch.read_text(encoding="utf-8-sig")
            args += ["--bn", WORKSPACE + "/registry-batch.reb"]
        if tool.get("supports_csvf", True):
            args += ["--csvf", tool["csv_name"]]
        return Plan("EZ " + tool["label"], source, output, [Step(args, tool["label"], timeout=s.timeout_seconds)],
                    configs=configs, expected_globs=["*.csv"])


class VolatilityAdapter(ToolAdapter):
    tool_id = "volatility"
    parameter_names = {"plugins", "renderer", "symbol_path"}

    def build(self, p, source, output, s, preview=False):
        try:
            catalog = json.loads(Path(s.plugin_path).read_text())
        except (OSError, ValueError) as exc:
            raise ValidationError("Volatility plugin catalog is unavailable.") from exc
        accepted = {name for names in catalog.values() for name in names}
        plugins = choices(p, "plugins", accepted)
        if not plugins:
            raise ValidationError("Select at least one supported plugin.")
        renderer = text(p, "renderer", "json")
        if renderer not in {"json", "pretty"}:
            raise ValidationError("Renderer must be json or pretty.")
        symbols = text(p, "symbol_path")
        if symbols:
            symbols = normalize(symbols)
            if not Path(symbols).is_dir() or not allowed(symbols, s.symbol_roots):
                raise ValidationError("Symbol path is unavailable or outside allowed roots.")
        prefix = executable(self.tool_id, ["vol", "vol3", "volatility3"], s, not preview)
        args = prefix + ["--offline", "-q", "-f", source, "-o", OUTPUT, "-r", renderer]
        if symbols:
            args += ["-s", symbols]
        extension = "json" if renderer == "json" else "txt"
        steps = [Step(args + [name], name, OUTPUT + "/results/" + name.replace(".", "_") + "." + extension,
                      s.timeout_seconds, True) for name in plugins]
        return Plan(self.tool_id, source, output, steps, parameters={"plugins": plugins, "renderer": renderer})


class TimelineAdapter(ToolAdapter):
    tool_id = "artifact-triage"
    parameter_names = {"timezone"}
    source_kind = "file_or_dir"

    def build(self, p, source, output, s, preview=False):
        zone = text(p, "timezone", "UTC")
        try:
            ZoneInfo(zone)
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise ValidationError("Unknown timeline time zone.") from exc
        extract = executable("log2timeline", ["log2timeline.py", "log2timeline"], s, not preview)
        export = executable("psort", ["psort.py", "psort"], s, not preview)
        return Plan(self.tool_id, source, output, [
            Step(extract + ["--storage_file", OUTPUT + "/timeline.plaso", source], "Extract timeline", timeout=s.timeout_seconds),
            Step(export + ["-o", "l2tcsv", "-w", OUTPUT + "/timeline.csv", "--output_time_zone", zone, OUTPUT + "/timeline.plaso"],
                 "Export timeline", timeout=s.timeout_seconds)], expected_files=["timeline.plaso", "timeline.csv"],
                    create_output_directory=True)


class FileTypeAdapter(ToolAdapter):
    tool_id = "filetype"
    parameter_names = {"mode", "recursive", "mismatch_only"}
    source_kind = "file_or_dir"

    def build(self, p, source, output, s, preview=False):
        mode = text(p, "mode", "mime")
        if mode not in {"mime", "brief", "full"}:
            raise ValidationError("Unsupported file identification mode.")
        recursive = flag(p, "recursive", True)
        mismatch_only = flag(p, "mismatch_only")
        if mismatch_only and mode != "mime":
            raise ValidationError("Mismatch filtering requires MIME mode.")
        args = executable(self.tool_id, ["file"], s, not preview)
        args += ["--mime-type", "-b"] if mode == "mime" else (["-b"] if mode == "brief" else [])
        args += ["--", "{selected_file}"]
        return Plan(self.tool_id, source, output, [Step(args, "Identify each selected file", timeout=10)],
                    parameters={"mode": mode, "recursive": recursive, "mismatch_only": mismatch_only}, operation="filetype")


ADAPTERS = {adapter.tool_id: adapter for adapter in (
    StringsAdapter(), ExifToolAdapter(), CarvingAdapter("foremost"), CarvingAdapter("scalpel"),
    BulkAdapter(), ZimmermanAdapter(), VolatilityAdapter(), TimelineAdapter(), FileTypeAdapter())}


def compile_plan(tool_id, payload, settings, repository, preview=False):
    adapter = ADAPTERS.get(tool_id)
    if not adapter:
        raise ValidationError("Unknown or unsupported workflow.")
    if not isinstance(payload, dict):
        raise ValidationError("Request must be a JSON object.")
    unknown = payload.keys() - {"case_id", "source_path", "output_path"} - adapter.parameter_names
    if unknown:
        raise ValidationError("Unknown workflow parameters: " + ", ".join(sorted(unknown)))
    case_id = text(payload, "case_id") or None
    case = repository.case(case_id) if case_id else None
    if case_id and not case:
        raise ValidationError("Case not found.")
    raw_source = text(payload, "source_path")
    source = normalize(raw_source) if raw_source else "<source_path>"
    if raw_source:
        if not allowed(source, settings.input_roots):
            raise ValidationError("Source is outside allowed input roots.")
        if not Path(source).exists() or not (Path(source).is_file() or Path(source).is_dir()):
            raise ValidationError("Source must be an existing regular file or directory.")
        if adapter.source_kind == "file" and not Path(source).is_file():
            raise ValidationError("Source must be a regular file.")
    elif not preview:
        raise ValidationError("Source path is required.")
    raw_output = text(payload, "output_path")
    if not raw_output and case:
        root = settings.output_roots[0] if settings.output_roots else "/cases"
        slug = re.sub(r"[^\w-]", "-", case.get("slug") or case_id)
        raw_output = str(Path(root) / slug / tool_id / (datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]))
    if not raw_output and not preview:
        raise ValidationError("Output folder is required.")
    output = normalize(raw_output) if raw_output else "<output_dir>"
    if raw_output:
        if not allowed(output, settings.output_roots):
            raise ValidationError("Output path is outside allowed roots.")
        if source != "<source_path>" and (Path(output) == Path(source) or Path(source) in Path(output).parents):
            raise ValidationError("Output must be separate from the input.")
        if Path(output).exists() and (not Path(output).is_dir() or any(Path(output).iterdir())):
            raise ValidationError("Output folder must be absent or empty; existing results are preserved.")
        if Path(output + ".log").exists():
            raise ValidationError("A run log already exists at this destination; choose a new output folder.")
    plan = adapter.build(payload, source, output, settings, preview)
    plan.max_output_bytes = settings.max_output_bytes
    input_record = {"path": source, "kind": "directory" if Path(source).is_dir() else "file",
                    "case_id": case_id, "artifact_id": None, "baseline_sha256": None,
                    "signature": signature(source) if raw_source else None}
    if input_record["kind"] == "directory" and not preview:
        input_record["members"] = directory_members(source)
    for item in (case or {}).get("artifacts", []):
        if item.get("path") and normalize(item["path"]) == source:
            input_record.update(artifact_id=item["id"], baseline_sha256=item.get("hash") or None)
            break
    return plan, case_id, input_record
