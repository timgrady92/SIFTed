"""Validated, serializable execution plans. Preview and execution share argv.

Only these adapters can create plans; HTTP clients cannot supply command text.
OUTPUT and WORKSPACE tokens are resolved by the worker inside its managed attempt.
"""
import os
import re
import shlex
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

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
    max_stdout_bytes: int | None = None


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
    postprocess: str | None = None
    input_paths: list[str] = field(default_factory=list)

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


def integer(payload, key, default=None, minimum=0, maximum=2**53 - 1):
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"{key} must be an integer from {minimum} to {maximum}.")
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


