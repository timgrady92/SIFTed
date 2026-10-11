"""Managed validation of native Zimmerman diagnostics and CSV exports."""
import csv
import re

CSV_FIELD_LIMIT = 16 * 1024 * 1024

STEMS = {
    "amcacheparser": "amcache",
    "appcompatcacheparser": "shimcache",
    "lecmd": "lnk",
    "jlecmd": "jumplist",
    "sbecmd": "shellbags",
    "rbcmd": "recyclebin",
    "recentfilecacheparser": "recentfilecache",
    "evtxecmd": "eventlogs",
    "mftecmd": "mft",
    "recmd": "registry",
}
REQUIRED_COLUMNS = {
    "appcompatcacheparser": {"Path", "CacheEntryPosition", "ControlSet"},
    "lecmd": {"SourceFile", "RelativePath", "TargetCreated"},
    "jlecmd": {"SourceFile", "AppId", "Path"},
    "sbecmd": {"BagPath", "AbsolutePath", "Slot"},
    "rbcmd": {"SourceName", "FileName", "FileSize", "DeletedOn"},
    "recentfilecacheparser": {"SourceFile", "Filename"},
    "evtxecmd": {"EventId", "RecordNumber", "TimeCreated", "Provider", "Channel"},
    "mftecmd": {"FileName", "EntryNumber", "SequenceNumber"},
    "recmd": {"HivePath", "HiveType", "KeyPath", "ValueName", "ValueData"},
}

ERROR_RECORD = re.compile(
    r"^\[(?:\d{4}-\d{2}-\d{2}[ T])?\d{2}:\d{2}:\d{2}(?:\.\d{1,9})? (?:ERR|FTL)\]|^Unhandled exception:|^Message: Error parsing shellbag"
)
RECENT_ERROR = re.compile(
    r"^(?:Error processing file |Error exporting data!|Unable to open |Unable to access )"
)


def diagnostic_lines(directory, check):
    for name in ("parser-log.txt", "parser-stderr.txt"):
        path = directory / name
        if path.is_symlink():
            raise ValueError("Parser diagnostic output must not be a symbolic link.")
        with path.open(encoding="utf-8", errors="replace") as handle:
            while line := handle.readline(256 * 1024):
                check()
                yield line


def process_native_exports(parameters, output, check):
    csv.field_size_limit(CSV_FIELD_LIMIT)
    tool_id = parameters["parser_id"]
    errors, outcomes = [], []
    for index, scope in enumerate(parameters["export_scopes"]):
        context = {"scope": scope, "source": parameters["selected_inputs"][index]}
        parsed = empty_batch = completed = False
        diagnostics = []
        try:
            for line in diagnostic_lines(output / scope, check):
                value = re.sub(r"^\[[^\]]+\]\s*", "", line).strip()
                parsed |= value == "Hive processing complete!"
                empty_batch |= value == "Found 0 key/value pairs across 1 file"
                completed |= value.startswith("Total search time:")
                if (
                    ERROR_RECORD.match(line)
                    or tool_id == "evtxecmd"
                    and re.search(r"Records included:.*Errors: [1-9][0-9,]*", value)
                    or tool_id == "recentfilecacheparser"
                    and RECENT_ERROR.match(line)
                ):
                    if len(diagnostics) < 10:
                        diagnostics.append(line.strip()[:1000])
        except (OSError, ValueError) as exc:
            diagnostics.append(str(exc))
        if diagnostics:
            errors.append(
                "Native parser reported incomplete processing for "
                + (scope or "source")
                + ":\n"
                + "\n".join(diagnostics)
            )
        scoped = list((output / scope).glob("*.csv"))
        if (
            not scoped
            and tool_id == "recmd"
            and parsed
            and empty_batch
            and completed
            and not diagnostics
        ):
            outcomes.append({**context, "status": "no_matching_batch_rows"})
            continue
        if (
            not scoped
            or tool_id == "recmd"
            and not (output / scope / "registry.csv").is_file()
        ):
            errors.append(
                "Parser produced no primary CSV exports for input scope "
                + (scope or "source")
                + ". Inspect parser-log.txt."
            )
            outcomes.append({**context, "status": "error"})
        else:
            outcomes.append(
                {**context, "status": "error" if diagnostics else "exported"}
            )
    files = sorted(output.rglob("*.csv"))
    counts, total = [], 0
    primary = None
    stem = STEMS[tool_id]
    for path in files:
        check()
        try:
            count = validate_export(tool_id, path, check)
        except (OSError, ValueError, csv.Error) as exc:
            errors.append(str(exc))
            for outcome in outcomes:
                if path.is_relative_to(output / outcome["scope"]):
                    outcome["status"] = "error"
            continue
        relative = path.relative_to(output).as_posix()
        counts.append({"file": relative, "entry_count": count})
        total += count
        if (
            primary is None
            or path.name == stem + ".csv"
            or tool_id == "amcacheparser"
            and path.name.endswith("UnassociatedFileEntries.csv")
        ):
            primary = relative
    return {
        "validation_errors": errors,
        "analysis": {
            "table": primary,
            "entry_count": total,
            "tables": counts,
            "csv_count": len(counts),
            "parser_id": tool_id,
            "parser_version": parameters["version"],
            "input_outcomes": outcomes,
            "ignore_transaction_logs": parameters.get(
                "ignore_transaction_logs", False
            ),
            "staged_inputs": bool(parameters.get("input_copies")),
        },
    }


def validate_export(tool_id, path, check):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Parser CSV output must not contain symbolic links.")
    required = REQUIRED_COLUMNS.get(tool_id, set())
    if tool_id == "jlecmd" and path.name.endswith("CustomDestinations.csv"):
        required = {"SourceFile", "AppId", "RelativePath"}
    if tool_id == "recmd" and path.name != STEMS[tool_id] + ".csv":
        required = set()  # Plugin tables have independent schemas.
    if tool_id == "amcacheparser":
        required = (
            {"FullPath", "SHA1"}
            if path.name.endswith("FileEntries.csv")
            else {"ProgramId"}
            if path.name.endswith("ProgramEntries.csv")
            else {"KeyName"}
        )
    with path.open(newline="", encoding="utf-8-sig", errors="strict") as handle:
        reader = csv.reader(handle, strict=True)
        header = next(reader, None)
        if (
            not header
            or any(not value.strip() for value in header)
            or len(header) != len(set(header))
        ):
            raise ValueError("Parser CSV has empty or duplicate columns: " + path.name)
        missing = {
            column
            for column in required
            if column.casefold() not in {value.casefold() for value in header}
        }
        if missing:
            raise ValueError(
                "Parser CSV is missing required columns: " + ", ".join(sorted(missing))
            )
        count = 0
        for row in reader:
            check()
            if row and len(row) != len(header):
                raise ValueError(
                    "Parser CSV contains a row with an inconsistent column count: "
                    + path.name
                )
            count += bool(row)
    return count
