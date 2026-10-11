"""Workflow adapters and the authoritative execution registry."""
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .volatility import VolatilityAdapter
from .carving import CarvingAdapter
from .zimmerman import ZimmermanAdapter
from .disk_tools import DISK_TOOL_IDS, DiskAdapter
from .examination_tools import EXAMINATION_TOOL_IDS, ExaminationAdapter
from .tool_base import (OUTPUT, Plan, Step, ToolAdapter, ValidationError, allowed,
                        choices, directory_members, executable, flag, normalize, signature, text)


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
        return Plan(self.tool_id, source, output, [Step(args, "Identify each selected file", timeout=s.timeout_seconds)],
                    parameters={"mode": mode, "recursive": recursive, "mismatch_only": mismatch_only}, operation="filetype")


ADAPTERS = {adapter.tool_id: adapter for adapter in (
    StringsAdapter(), ExifToolAdapter(), CarvingAdapter("foremost"), CarvingAdapter("scalpel"),
    BulkAdapter(), ZimmermanAdapter(), VolatilityAdapter(), TimelineAdapter(), FileTypeAdapter(),
    *(DiskAdapter(tool) for tool in DISK_TOOL_IDS), *(ExaminationAdapter(tool) for tool in EXAMINATION_TOOL_IDS))}


def compile_plan(tool_id, payload, settings, repository, preview=False):
    adapter = ADAPTERS.get(tool_id)
    if not adapter:
        raise ValidationError("Unknown or unsupported workflow.")
    if not isinstance(payload, dict):
        raise ValidationError("Request must be a JSON object.")
    unknown = payload.keys() - {"case_id", "source_path", "output_path", "workspace_input"} - adapter.parameter_names
    if unknown:
        raise ValidationError("Unknown workflow parameters: " + ", ".join(sorted(unknown)))
    case_id = text(payload, "case_id") or None
    case = repository.case(case_id) if case_id else None
    if case_id and not case:
        raise ValidationError("Case not found.")
    raw_source = text(payload, "source_path")
    source = normalize(raw_source) if raw_source else "<source_path>"
    workspace_input = text(payload, "workspace_input")
    if workspace_input:
        from .evidence_workspace import select_input
        if not case:
            raise ValidationError("Workspace analysis requires its selected case.")
        selected = select_input(case, repository, workspace_input)
        if normalize(selected["path"]) != source:
            raise ValidationError("Workspace evidence does not match the requested source.")
    derived = repository.artifact_by_path(source) if raw_source else None
    if derived and (not derived.get("complete") or derived.get("case_id") != case_id or derived.get("status") != "success"):
        derived = None
    if raw_source:
        if not allowed(source, settings.input_roots) and not (derived and allowed(source, settings.output_roots)):
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
    plan = adapter.build({k: v for k, v in payload.items() if k != "workspace_input"}, source, output, settings, preview)
    context = None
    context_run_id = text(payload, "context_run_id")
    if context_run_id:
        context = repository.run(context_run_id)
        if not context or context["status"] != "success" or context.get("case_id") != case_id or context["plan"]["source"] != source:
            raise ValidationError("Context run must be a successful run for the same case and image.")
        context_params = context["plan"].get("parameters", {})
        if context["tool"] != "mmls" and any(context_params.get(key) != plan.parameters.get(key) for key in ("offset_sector", "sector_size")):
            raise ValidationError("Filesystem geometry does not match the context run.")
        if context["tool"] == "mmls" and context.get("analysis", {}).get("sector_size") != plan.parameters.get("sector_size"):
            raise ValidationError("Disk sector size does not match the partition map.")
        if workspace_input and context["tool"] == "mmls":
            from .evidence_workspace import partition_choices
            rows = partition_choices(context, repository, settings)
            if plan.parameters.get("offset_sector") not in {row["offset_sector"] for row in rows}:
                raise ValidationError("Selected filesystem is not in the verified partition map.")
        plan.parameters["context_run_id"] = context_run_id
    plan.max_output_bytes = settings.max_output_bytes
    input_record = {"path": source, "kind": "directory" if Path(source).is_dir() else "file",
                    "case_id": case_id, "artifact_id": None, "baseline_sha256": None,
                    "signature": signature(source) if raw_source else None}
    if derived:
        input_record.update(artifact_id=derived["id"], baseline_sha256=derived["sha256"], source_run_id=derived["run_id"])
    if context:
        input_record["baseline_sha256"] = context.get("input_sha256")
        input_record["context_run_id"] = context_run_id
    if plan.input_paths and raw_source:
        input_record["image_paths"] = plan.input_paths
        input_record["related_files"] = []
        for path in plan.input_paths[1:]:
            if not allowed(path, settings.input_roots):
                raise ValidationError("Image segment is outside allowed input roots.")
            baseline = next((entry["sha256"] for entry in (context or {}).get("input_files", []) if entry["path"] == path), None)
            input_record["related_files"].append({"path": path, "signature": signature(path), "baseline_sha256": baseline})
    for path in plan.auxiliary_paths:
        if not allowed(path, settings.input_roots):
            raise ValidationError("Auxiliary input is outside allowed input roots.")
        input_record.setdefault("related_files", []).append({"path": path, "signature": signature(path), "baseline_sha256": None})
    if input_record["kind"] == "directory" and not preview:
        input_record["members"] = directory_members(source)
    for item in (case or {}).get("artifacts", []):
        if item.get("path") and normalize(item["path"]) == source:
            baseline = item.get("hash") or input_record["baseline_sha256"]
            if baseline and input_record["baseline_sha256"] and baseline != input_record["baseline_sha256"]:
                raise ValidationError("Registered evidence baseline differs from the producing or context run.")
            input_record.update(artifact_id=item["id"], baseline_sha256=baseline)
            break
    return plan, case_id, input_record
