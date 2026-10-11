"""Discover and plan the installed Volatility 3, without a bundled tool checkout."""
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from .tool_base import (OUTPUT, Plan, Step, ToolAdapter, ValidationError, allowed,
                        choices, executable, flag, normalize, signature, text)

_CACHE = {}
PROBE = Path(__file__).with_name("volatility_probe.py")
JSON_LIMIT = 64 * 1024 * 1024


def integer_value(value, name):
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|[0-9]+)", value):
        try:
            return int(value, 0)
        except ValueError:
            return int(value, 10)
    raise ValidationError(name + " must be an integer or a decimal/hexadecimal integer string.")


def discover(settings, refresh=False):
    prefix = executable("volatility", ["vol"], settings)
    key = tuple(prefix)
    identity = signature(prefix[0])
    cached = _CACHE.get(key)
    if not refresh and cached and cached[0] == identity and time.monotonic() - cached[1] < 30:
        return cached[2]
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", Path(prefix[0]).name):
        interpreter = [prefix[0]]
        location = str(Path(prefix[1]).parent) if len(prefix) > 1 else ""
    else:
        try:
            with open(prefix[0], "rb") as handle:
                line = handle.readline(4096).decode("utf-8")
            interpreter = shlex.split(line[2:].strip()) if line.startswith("#!") else []
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValidationError("Cannot inspect the installed Volatility console script.") from exc
        location = str(Path(prefix[0]).parent)
        if not interpreter or not any(re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", Path(arg).name) for arg in interpreter):
            raise ValidationError("Configure Volatility's Python console script, or a Python executable plus vol.py.")
    if not shutil.which(interpreter[0]):
        raise ValidationError("Volatility's Python interpreter is unavailable.")
    try:
        result = subprocess.run([*interpreter, str(PROBE), location], capture_output=True,
                                text=True, timeout=30, check=True)
        data = json.loads(result.stdout)
        if not data["version"].startswith("2.") or not data["plugins"]:
            raise ValueError("Expected an installed Volatility 3 framework with plugins.")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise ValidationError("Volatility 3 discovery failed: " + detail[-2000:]) from exc
    data["argv_prefix"] = prefix
    data["identity"] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    _CACHE[key] = (identity, time.monotonic(), data)
    return data


# Exact class names avoid CLI substring selection and deprecated aliases.
BUNDLES = {
    "windows": [
        ("Processes", ["windows.info.Info", "windows.pslist.PsList", "windows.pstree.PsTree", "windows.psscan.PsScan"]),
        ("Network", ["windows.netscan.NetScan", "windows.netstat.NetStat"]),
        ("Malware", ["windows.malware.malfind.Malfind", "windows.malware.psxview.PsXView", "windows.malware.ldrmodules.LdrModules"]),
    ],
    "linux": [
        ("Processes", ["linux.pslist.PsList", "linux.pstree.PsTree", "linux.psaux.PsAux"]),
        ("Network", ["linux.ip.Addr", "linux.ip.Link", "linux.sockstat.Sockstat"]),
        ("Files", ["linux.lsof.Lsof", "linux.mountinfo.MountInfo", "linux.pagecache.Files"]),
    ],
    "mac": [("Processes", ["mac.pslist.PsList", "mac.pstree.PsTree", "mac.psaux.Psaux"])],
    "general": [("Identify image", ["banners.Banners"])],
}


class VolatilityAdapter(ToolAdapter):
    tool_id = "volatility"
    parameter_names = {"plugins", "plugin_options", "renderer", "symbol_path", "offline"}

    def validate_execution(self, plan, settings):
        installed = discover(settings, refresh=True)
        if installed["identity"] != plan.parameters["installation_identity"]:
            raise ValidationError("Volatility installation changed while queued; create a fresh run.")
        symbols = plan.parameters["symbol_path"]
        if symbols and (not Path(symbols).is_dir() or not allowed(symbols, settings.symbol_roots)):
            raise ValidationError("Symbol directory is no longer available or allowed.")
        if settings.volatility_symbols != plan.parameters["managed_symbols"]:
            raise ValidationError("Managed symbol directory changed while queued; create a fresh run.")
        Path(settings.volatility_symbols).mkdir(parents=True, exist_ok=True)

    def build(self, p, source, output, s, preview=False):
        installed = discover(s)
        selected = choices(p, "plugins", installed["plugins"])
        if not selected:
            raise ValidationError("Select at least one installed plugin.")
        renderer = text(p, "renderer", "json")
        if renderer not in {"json", "jsonl", "pretty"}:
            raise ValidationError("Renderer must be json, jsonl or pretty.")
        offline = flag(p, "offline")
        symbols = text(p, "symbol_path")
        if symbols:
            symbols = normalize(symbols)
            if not Path(symbols).is_dir() or not allowed(symbols, s.symbol_roots) or ";" in symbols:
                raise ValidationError("Symbol path must be one directory within configured symbol roots.")
        options = p.get("plugin_options", {})
        if not isinstance(options, dict) or set(options) - set(selected):
            raise ValidationError("Plugin options must be an object keyed by selected plugin names.")
        prefix = installed["argv_prefix"] + ["-q", "-f", source, "-r", renderer]
        if offline:
            prefix += ["--offline"]
        symbol_dirs = [symbols, s.volatility_symbols] if symbols else [s.volatility_symbols]
        if any(";" in path for path in symbol_dirs):
            raise ValidationError("Symbol directory paths must not contain semicolons.")
        prefix += ["-s", ";".join(symbol_dirs)]
        steps, auxiliary, saved = [], [], {}
        for name in selected:
            declarations = {opt["name"]: opt for opt in installed["plugins"][name]["options"]}
            values = options.get(name, {})
            if not isinstance(values, dict) or set(values) - set(declarations):
                raise ValidationError("Unknown options for " + name)
            arguments = []
            normalized_values = {}
            for key, spec in declarations.items():
                if key not in values:
                    if spec["required"]:
                        raise ValidationError(name + " requires " + key)
                    continue
                value = values[key]
                kind = spec["type"]
                if kind == "integer":
                    value = integer_value(value, name + "." + key)
                elif kind == "integer_list" and isinstance(value, list):
                    value = [integer_value(v, name + "." + key) for v in value]
                valid = ((kind == "boolean" and isinstance(value, bool)) or
                         (kind == "integer" and type(value) is int) or
                         (kind in {"string", "file"} and isinstance(value, str) and bool(value) and "\x00" not in value) or
                         (kind.endswith("_list") and isinstance(value, list) and (bool(value) or not spec["required"]) and all(
                             type(v) is int if kind == "integer_list" else isinstance(v, str) and bool(v) and "\x00" not in v
                             for v in value)))
                if not valid or (spec["choices"] is not None and value not in spec["choices"]):
                    raise ValidationError(f"Invalid {name}.{key}: expected {kind}.")
                normalized_values[key] = value
                if kind == "boolean":
                    if value:
                        arguments.append(spec["flag"])
                elif kind == "file":
                    path = normalize(value)
                    if not Path(path).is_file() or not allowed(path, s.input_roots):
                        raise ValidationError(f"{name}.{key} must be an existing file within input roots.")
                    if path == output or Path(output) in Path(path).parents:
                        raise ValidationError("Plugin input files must be separate from output.")
                    auxiliary.append(path)
                    arguments.append(spec["flag"] + "=" + Path(path).as_uri())
                elif kind.endswith("_list"):
                    if kind == "string_list" and any(v.startswith("-") for v in value):
                        raise ValidationError("List values must not begin with '-'.")
                    arguments += [spec["flag"], *map(str, value)]
                else:
                    arguments.append(spec["flag"] + "=" + str(value))
            folder = OUTPUT + "/plugins/" + name
            filename = folder + ("/result.txt" if renderer == "pretty" else "/result." + renderer)
            steps.append(Step(prefix + ["--save-config", folder + "/config.json", "-o", folder, name, *arguments], name, filename,
                              s.timeout_seconds, True, JSON_LIMIT if renderer == "json" else None))
            saved[name] = normalized_values
        snapshot = {**installed, "plugins": {name: installed["plugins"][name] for name in selected}}
        return Plan(self.tool_id, source, output, steps,
                    configs={"volatility-installation.json": json.dumps(snapshot, indent=2)},
                    auxiliary_paths=list(dict.fromkeys(auxiliary)), postprocess="volatility",
                    expected_files=["plugins/" + name + "/config.json" for name in selected],
                    postprocess_on_failure=True,
                    parameters={"plugins": selected, "plugin_options": saved, "renderer": renderer,
                                "offline": offline, "symbol_path": symbols,
                                "managed_symbols": s.volatility_symbols,
                                "version": installed["version"], "installation_identity": installed["identity"]})
