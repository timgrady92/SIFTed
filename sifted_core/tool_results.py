"""Streaming, conservative interpretation; raw tool output is always retained."""
import csv
import json
from pathlib import Path
import re
from .json_rows import json_lines, tree_rows
from .carving import verify_recoveries
from .zimmerman import process_exports
from .file_triage import build_index, INDEX_NAME


PARTITION = re.compile(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$")
FILE_ENTRY = re.compile(r"^\s*([A-Za-z-])/([A-Za-z-])\s+(\*\s+)?(\d+(?:-\d+){0,2})(\(realloc\))?:\s(.*)$")


def process_results(plan, output, check, step_results=None):
    if output.is_symlink():
        raise ValueError("Tool output directory must not be a symbolic link.")
    tool = plan.postprocess
    if tool == "carving":
        return verify_recoveries(plan, output, check)
    if tool == "volatility":
        summaries, errors = [], []
        results = {r["label"]: r for r in step_results or []}
        for step in plan.steps:
            check()
            result = results.get(step.label)
            relative = "plugins/" + step.label + ("/result.txt" if plan.parameters["renderer"] == "pretty"
                                                 else "/result." + plan.parameters["renderer"])
            summary = {"plugin": step.label, "file": relative, "status": "skipped", "row_count": None}
            if result:
                summary.update(status="error" if result["return_code"] else "success",
                               return_code=result["return_code"], error=result.get("error"))
            if result and not result["return_code"]:
                try:
                    path = output / relative
                    if path.is_symlink():
                        raise ValueError("Plugin result must be a regular file.")
                    if plan.parameters["renderer"] == "json":
                        with path.open(encoding="utf-8", errors="strict") as handle:
                            rows = json.load(handle)
                        if not isinstance(rows, list):
                            raise ValueError("Expected a JSON array of result rows.")
                        summary["row_count"] = sum(1 for row in tree_rows(rows, check))
                    elif plan.parameters["renderer"] == "jsonl":
                        count = 0
                        with path.open("rb") as handle:
                            for root in json_lines(handle):
                                count += sum(1 for row in tree_rows([root], check))
                        summary["row_count"] = count
                    elif not path.is_file() or not path.stat().st_size:
                        raise ValueError("Plugin produced no table output.")
                except (OSError, ValueError, UnicodeError) as exc:
                    summary.update(status="error", error="Invalid plugin output: " + str(exc))
                    errors.append(step.label + ": " + summary["error"])
            summaries.append(summary)
        (output / "plugin-summary.json").write_text(json.dumps(summaries, indent=2))
        return {"plugin_results": summaries, "validation_errors": errors}
    if tool == "zimmerman":
        return process_exports(plan, output, check)
    if tool in {"icat", "blkcat", "blkls"}:
        return {"analysis": {"derived_file": plan.expected_files[0],
                             "artifact_kind": "extracted_file" if tool == "icat" else "filesystem_block_sample"}}
    raw = output / (tool + ".txt")
    if raw.is_symlink() or not raw.is_file():
        raise ValueError("Tool output is missing or is a symbolic link.")
    if tool in {"blkstat", "blkcalc"}:
        with raw.open("rb") as handle:
            text = handle.read(65536).decode("utf-8", errors="replace")
        if tool == "blkcalc":
            value = text.strip()
            reported = value if re.fullmatch(r"\d+", value) else None
            mapped = reported
            if plan.parameters["direction"] == "original_to_unallocated":
                mapped = None
                ordinal = 0
                with (output / "mapping_units.txt").open(encoding="utf-8", errors="strict") as units:
                    for line in units:
                        check()
                        match = re.fullmatch(r"(\d+)\|f\s*", line)
                        if match:
                            if int(match[1]) == plan.parameters["block_address"]:
                                mapped = str(ordinal)
                            ordinal += 1
            return {"analysis": {"mapped_address": mapped, "reported_address": reported,
                                 "direction": plan.parameters["direction"], "address_space": "filesystem_data_unit"}}
        state = "unknown"
        for line in text.splitlines():
            value = line.strip().casefold()
            if value in {"allocated", "allocation status: allocated"}:
                state = "allocated"
            elif value in {"not allocated", "unallocated", "allocation status: unallocated", "allocation status: not allocated"}:
                state = "unallocated"
        return {"analysis": {"allocation_state": state, "address_space": "filesystem_data_unit"}}
    columns = (["Index", "Slot", "Kind", "Start Sector", "End Sector", "Length Sectors", "Size Bytes", "Description"]
               if tool == "mmls" else ["Metadata Address", "Name", "Kind", "Deleted", "Reallocated"])
    table = tool + ".csv"
    count = deleted = unparsed = 0
    sector_size = None
    with raw.open(encoding="utf-8", errors="replace") as source, (output / table).open("x", newline="", encoding="utf-8") as target, (output / "unparsed.txt").open("x", encoding="utf-8") as warnings:
        writer = csv.writer(target)
        writer.writerow(columns)
        for line in source:
            check()
            if not line.strip():
                continue
            if tool == "mmls":
                units = re.fullmatch(r"Units are in (\d+)-byte sectors\s*", line.strip())
                if units:
                    sector_size = int(units[1])
                    continue
                match = PARTITION.fullmatch(line.rstrip("\r\n"))
                if not match:
                    if line.lstrip().startswith(("Slot", "Offset Sector:")) or "Partition Table" in line:
                        continue
                    warnings.write(line)
                    unparsed += 1
                    continue
                index, slot, start, end, length, size, description = match.groups()
                kind = "metadata" if slot == "Meta" else "unallocated" if slot == "-------" else "allocated"
                writer.writerow([index, slot, kind, start, end, length, int(length) * sector_size if sector_size else "", description])
            else:
                match = FILE_ENTRY.fullmatch(line.rstrip("\r\n"))
                if not match:
                    warnings.write(line)
                    unparsed += 1
                    continue
                name_type, meta_type, removed, address, reallocated, name = match.groups()
                is_dir = "d" in {name_type.casefold(), meta_type.casefold()} or ("v" in {name_type.casefold(), meta_type.casefold()} and Path(name).name == "$OrphanFiles")
                kind = "directory" if is_dir else "file" if "r" in {name_type.casefold(), meta_type.casefold()} else "other"
                writer.writerow([address, name, kind, "Yes" if removed else "No", "Yes" if reallocated else "No"])
                deleted += bool(removed)
            count += 1
    if not unparsed:
        (output / "unparsed.txt").unlink()
    if count == 0 and tool == "mmls":
        raise ValueError("mmls produced no recognized partition entries; inspect raw output.")
    if count == 0 and unparsed:
        raise ValueError("Tool produced no recognized listing entries; inspect raw output and unparsed.txt.")
    analysis = {"table": table, "entry_count": count, "deleted_count": deleted,
                "unparsed_lines": unparsed, "sector_size": sector_size}
    if tool == "fls":
        build_index(output, check)
        analysis["inventory"] = INDEX_NAME
    return {"analysis": analysis}
