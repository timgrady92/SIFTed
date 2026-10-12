"""Evidence selection and contextual actions projected from existing case/run state.

This module never queues work. Adapters remain authoritative for every preview and
execution; recommendations are bounded observations, not forensic conclusions.
"""
from pathlib import Path
import csv
import hashlib
from itertools import islice

from .catalog import EZ_TOOL_CATALOG
from .tool_base import ValidationError, allowed, executable, normalize
from .zimmerman import resolve_ez_tool


SPECIALIZED = {
    "evtx": ("evtxecmd",), "mft": ("mftecmd",), "shortcut": ("lecmd",),
    "jump_list": ("jlecmd",), "recycle_bin": ("rbcmd",),
    "recent_cache": ("recentfilecacheparser",), "sqlite": ("sqlecmd",),
}
from .evidence_profile import LABELS, profile, interpretation
from .tool_base import signature
from .integrity import IntegrityFailure


def workspace_inputs(case, repository):
    """Keep original evidence and material outputs distinct from supporting reports."""
    values = [{**item, "key": "e:" + item["id"], "origin": "registered"}
              for item in case.get("artifacts", []) if item.get("status") != "retired"]
    runs = {run["id"]: run for run in repository.runs(case_id=case["id"])}
    for item in repository.derived_inputs(case["id"]):
        run = runs[item["run_id"]]
        name = item["name"]
        summary = run.get("analysis", {})
        kind = summary.get("artifact_kind")
        material = name == summary.get("derived_file")
        if run["tool"] in {"foremost", "scalpel"}:
            material = "/" in name and not name.startswith("_sifted/")
            kind = "carved_file"
        if name.startswith("blobs/") and summary.get("parser_id") == "sqlecmd":
            material, kind = True, "extracted_file"
        if run["tool"] == "volatility":
            captures = {step.get("stdout") for step in run["plan"]["steps"]}
            material = name.startswith("plugins/") and not any(
                path and path.endswith("/" + name) for path in captures
            ) and not name.endswith("/config.json")
            kind = "extracted_file"
        if material:
            values.append({**item, "key": "d:" + str(item["id"]), "origin": "derived",
                           "label": name, "hash": item["sha256"], "type": "derived_file",
                           "source_run_id": run["id"], "artifact_kind": kind})
    return values


def select_input(case, repository, key):
    item = next((item for item in workspace_inputs(case, repository) if item["key"] == key), None)
    if not item:
        raise ValidationError("Evidence input does not belong to this case or is not a complete material output.")
    return item


def identify(item, settings):
    observed = {"kind": "unknown", "label": LABELS["unknown"], "basis": "Intake required",
                "mime": None, "available": False, "note": ""}
    roots = settings.input_roots if item["origin"] == "registered" else settings.output_roots
    path = item["path"]
    if not allowed(path, roots):
        return {**observed, "note": "Evidence is outside the configured roots."}
    try:
        if item["origin"] == "registered":
            if item.get("status") != "ready":
                return {**observed, "note": "Evidence intake: " + item.get("status", "needs_intake") + ". Verify evidence before analysis."}
            observed = interpretation(item, item["profile"])
            if signature(path) != item["profile"]["signature"]:
                return {**observed, "available": False, "note": "Evidence has changed since verification. Reverify it before analysis."}
            return observed
        return interpretation(item, profile(path, settings))
    except (OSError, ValueError, IntegrityFailure):
        return {**observed, "available": False, "note": "Evidence is missing, unreadable, or changed."}


def resolve_actions(item, observed, settings, runs, context=None):
    """Single action catalog, with native availability and persisted result reuse."""
    kind = observed["kind"]
    definitions = []

    def add(tool, label, description, group="examination", parser=None, parameters=None, recommended=False):
        definitions.append({"tool": tool, "parser": parser, "label": label, "description": description,
                            "group": group, "parameters": parameters or {}, "recommended": recommended})

    add("filetype", "Identify content", "Identify formats with native file / libmagic.", recommended=kind in {"unknown", "block"})
    if kind != "directory":
        add("xxd", "Inspect bytes", "Read a bounded hexadecimal sample.", recommended=kind in {"unknown", "block"})
        add("strings", "Extract strings", "Find printable strings and their byte offsets.", recommended=kind in {"unknown", "block", "memory"})
    if kind not in {"block", "ewf"}:
        add("exiftool", "Read embedded metadata", "Inspect fields reported by ExifTool.", recommended=kind == "pdf")
    if kind != 'directory' and item.get('artifact_kind') in {'extracted_file', 'carved_file'}:
        add('clamscan', 'Check local malware signatures', 'Compare captured bytes with the installed ClamAV signatures; no matches do not establish safety.')
    if kind == "text":
        add("head", "Read text", "Read up to 64 KiB.", recommended=True)
    if kind == "pdf":
        add("pdfinfo", "Read PDF properties", "Inspect document properties and security flags.", recommended=True)
        add("pdftotext", "Extract PDF text", "Extract the first five pages of available text.", recommended=True)
    if kind in {"disk", "filesystem", "ewf"}:
        add("mmls", "Map partitions", "Locate partition starts in disk sectors.", "structure", recommended=kind != "filesystem" and not context)
        params = {k: context["plan"]["parameters"][k] for k in ("offset_sector", "sector_size")
                  if context and k in context["plan"]["parameters"]}
        if context:
            params["context_run_id"] = context["id"]
        add("fsstat", "Describe filesystem", "Inspect filesystem geometry at the selected offset.", "structure", parameters=params,
            recommended=kind == "filesystem" or bool(context))
        add("fls", "Browse files", "Build an inventory of names and metadata addresses.", "structure", parameters=params,
            recommended=kind == "filesystem" or bool(context))
    if kind == "memory":
        add("volatility", "Examine memory", "Choose plugins discovered from the installed Volatility 3.", "investigation", recommended=True)
    if kind in {"disk", "filesystem", "directory"}:
        add("artifact-triage", "Build a timeline", "Extract and export events with Plaso.", "investigation")
    if kind in {"disk", "filesystem", "memory", "unknown"}:
        add("bulk-extractor", "Find forensic features", "Scan the raw source for features such as email addresses.", "investigation")
        add("foremost", "Carve files", "Recover content by signatures with Foremost.", "recovery")
        add("scalpel", "Carve with selected profiles", "Recover content with reviewed Scalpel profiles.", "recovery")
    parsers = list(SPECIALIZED.get(kind, ()))
    if kind == "registry":
        parsers = ["recmd"]
        identity = observed.get("registry_identity", "").casefold()
        if "amcache" in identity:
            parsers.append("amcacheparser")
        if identity.endswith("system"):
            parsers.append("appcompatcacheparser")
    if kind == "directory":
        parsers = [tool for tool, spec in EZ_TOOL_CATALOG.items() if spec["input_mode"] != "file"]
    for parser in parsers:
        spec = EZ_TOOL_CATALOG[parser]
        add("eric-zimmerman", spec["label"], spec["description"], "investigation", parser,
            {"tool_id": parser}, recommended=kind != "directory")
    path = normalize(item["path"])
    relevant = [r for r in runs if normalize(r["source_path"]) == path]
    for action in definitions:
        action["id"] = action["parser"] or action["tool"]
        reason = None
        try:
            if action["parser"]:
                spec = resolve_ez_tool(action["parser"], settings)
                if not spec["installed"]:
                    reason = spec["error"]
            else:
                candidates = {"volatility": ["vol", "volatility3"], "bulk-extractor": ["bulk_extractor"],
                              "filetype": ["file"], "artifact-triage": ["log2timeline.py", "log2timeline"]}
                native_id = "volatility" if action["tool"] == "volatility" else "log2timeline" if action["tool"] == "artifact-triage" else action["tool"]
                executable(native_id, candidates.get(action["tool"], [action["tool"]]), settings)
                if action['tool'] == 'clamscan':
                    from .clamav import databases
                    databases(settings)
                if action["tool"] == "volatility":
                    from . import volatility
                    if not volatility.discover(settings)["plugins"]:
                        reason = "No supported Volatility 3 plugins were discovered."
                if action["tool"] in {"foremost", "scalpel"}:
                    from .carving import available_types
                    if not available_types(action["tool"], settings):
                        reason = "No supported carving profiles were discovered."
                if action["tool"] == "artifact-triage":
                    executable("psort", ["psort.py", "psort"], settings)
        except ValidationError as exc:
            reason = str(exc)
        action.update(enabled=observed["available"] and not reason,
                      reason=observed["note"] if not observed["available"] else reason)
        matches = [r for r in relevant if r["tool"] == action["tool"]
                   and (not action["parser"] or r["plan"].get("parameters", {}).get("parser_id") == action["parser"])
                   and all(r["plan"].get("parameters", {}).get(k) == v for k, v in action["parameters"].items()
                           if k not in {"context_run_id", "tool_id"})
                   and (not item.get("hash") or r.get("input_sha256") == item["hash"])]
        successful = [r for r in matches if r["status"] == "success"]
        latest = max(successful, key=lambda r: r["created_at"], default=None)
        action["result_run_id"] = latest["id"] if latest else None
    return definitions


def validate_context(context, item, case_id):
    if (not context or context.get("case_id") != case_id or context["status"] != "success"
            or normalize(context["source_path"]) != normalize(item["path"])
            or context["tool"] not in {"fsstat", "fls"}
            or item.get("hash") and context.get("input_sha256") != item["hash"]):
        raise ValidationError("Filesystem context must be a successful run for this case and evidence baseline.")
    return context


def partition_choices(run, repository, settings):
    """Only link bounded, hash-verified rows of a successful partition map."""
    sector_size = run.get("analysis", {}).get("sector_size")
    if run["status"] != "success" or run["tool"] != "mmls" or sector_size not in {512, 1024, 2048, 4096}:
        return []
    table = str(Path(run["output_path"]) / run.get("analysis", {}).get("table", "mmls.csv"))
    entry = next((x for x in repository.artifacts(run["id"]) if x["path"] == table and x.get("complete")), None)
    if not entry or not allowed(table, settings.output_roots):
        return []
    try:
        path = Path(table)
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            return []
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            return []
        import io
        rows = csv.DictReader(io.StringIO(content.decode("utf-8")))
        result = []
        for row in islice(rows, 100):
            if row.get("Kind") != "allocated":
                continue
            start = int(row["Start Sector"])
            length = int(row["Length Sectors"])
            if 0 <= start <= 2**53 - 1 and length > 0:
                result.append({"offset_sector": start, "sector_size": sector_size,
                               "description": row["Description"], "length_sectors": length})
        return result
    except (OSError, UnicodeError, ValueError, KeyError, csv.Error):
        return []
