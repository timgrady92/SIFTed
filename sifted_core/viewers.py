"""Bounded result parsers for the file viewer."""
import json
import os
import re
from pathlib import Path
from flask import current_app
from .tables import CsvTables

def read_text_preview(path, max_bytes=1024 * 1024):
    with open(path, "rb") as handle:
        data = handle.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    text = data.decode("utf-8", errors="replace")
    return text, truncated


def coerce_table_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True)
    return str(value)


def build_table_from_rows(rows, columns):
    normalized_columns = [
        col.get("name") if isinstance(col, dict) and col.get("name") else str(col)
        for col in (columns or [])
    ]
    row_values = []
    if rows and all(isinstance(row, dict) for row in rows):
        if not normalized_columns:
            normalized_columns = sorted({key for row in rows for key in row.keys()})
        for row in rows:
            row_values.append([row.get(col, "") for col in normalized_columns])
    elif rows and all(isinstance(row, (list, tuple)) for row in rows):
        max_len = max((len(row) for row in rows), default=0)
        if not normalized_columns:
            normalized_columns = [f"Column {i + 1}" for i in range(max_len)]
        for row in rows:
            padded = list(row) + [""] * (len(normalized_columns) - len(row))
            row_values.append(padded[: len(normalized_columns)])
    elif rows:
        normalized_columns = normalized_columns or ["Value"]
        row_values = [[row] for row in rows]

    return normalized_columns, row_values


def build_table_from_list(items):
    if not items:
        return [], []
    if all(isinstance(item, dict) for item in items):
        columns = sorted({key for item in items for key in item.keys()})
        rows = [[item.get(col, "") for col in columns] for item in items]
        return columns, rows
    if all(isinstance(item, (list, tuple)) for item in items):
        max_len = max((len(item) for item in items), default=0)
        columns = [f"Column {i + 1}" for i in range(max_len)]
        rows = [list(item) + [""] * (max_len - len(item)) for item in items]
        return columns, rows
    return ["Value"], [[item] for item in items]


def parse_csv_table(path, row_limit=500, max_bytes=1024 ** 3, row_offset=0):
    cache_path = Path(current_app.config["DATABASE_PATH"]).with_suffix(".tables.sqlite3")
    return CsvTables(cache_path).page(path, row_offset, row_limit, max_bytes)


def parse_strings_table(path, row_limit=500, max_bytes=50 * 1024 * 1024, row_offset=0):
    """Parse strings output (with optional offsets) into table data structure."""
    try:
        file_size = os.path.getsize(path)
    except OSError:
        raise ValueError("Unable to read file size.")
    if file_size > max_bytes:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"File is too large for table view ({size_mb:.1f} MB).")

    # Pattern for strings with hex offset (e.g., "   1234 some string here")
    offset_pattern = re.compile(r"^\s*([0-9a-fA-F]+)\s+(.+)$")

    row_offset = max(0, row_offset)
    row_limit = max(0, row_limit)
    rows = []
    has_offsets = None  # Will be determined from first line
    total_rows = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            line_num = 0
            for line in handle:
                line_num += 1
                line = line.rstrip("\n\r")
                if not line:
                    continue

                match = offset_pattern.match(line)
                if has_offsets is None:
                    has_offsets = bool(match)

                if has_offsets and match:
                    file_offset = match.group(1)
                    content = match.group(2)
                    row = [str(line_num), file_offset, content]
                else:
                    row = [str(line_num), line]

                row_index = total_rows
                if row_index >= row_offset and len(rows) < row_limit:
                    rows.append(row)
                total_rows += 1
    except OSError:
        raise ValueError("Unable to read file.")

    if total_rows == 0:
        raise ValueError("No string data found.")

    if has_offsets:
        columns = ["Line", "Offset (hex)", "String"]
    else:
        columns = ["Line", "String"]

    truncated = total_rows > row_offset + len(rows)
    columns = [coerce_table_value(col) for col in columns]
    rows = [[coerce_table_value(value) for value in row] for row in rows]

    return {"columns": columns, "rows": rows}, total_rows, truncated


def parse_foremost_audit(path, row_limit=500, max_bytes=10 * 1024 * 1024, row_offset=0):
    """Parse Foremost audit.txt into table data structure."""
    try:
        file_size = os.path.getsize(path)
    except OSError:
        raise ValueError("Unable to read file size.")
    if file_size > max_bytes:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"File is too large for table view ({size_mb:.1f} MB).")

    # Pattern for carved files: "   12345:   filename.ext"
    file_pattern = re.compile(r"^\s*(\d+):\s+(\S+)")
    # Section header pattern
    section_pattern = re.compile(r"^Foremost.*|^Audit File|^Invocation:|^Output directory:|^Configuration file:|^-----|^File:")

    row_offset = max(0, row_offset)
    row_limit = max(0, row_limit)
    rows = []
    current_type = "unknown"
    total_rows = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n\r")

                # Skip headers and section markers
                if section_pattern.match(line) or not line.strip():
                    continue

                # Check for file type sections (e.g., "jpg:")
                if line.endswith(":") and not line.startswith(" "):
                    current_type = line[:-1].strip()
                    continue

                # Parse carved file entries
                match = file_pattern.match(line)
                if match:
                    file_offset = match.group(1)
                    filename = match.group(2)
                    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                    row = [current_type, file_offset, filename, ext]
                    row_index = total_rows
                    if row_index >= row_offset and len(rows) < row_limit:
                        rows.append(row)
                    total_rows += 1
    except OSError:
        raise ValueError("Unable to read file.")

    if total_rows == 0:
        raise ValueError("No carved files found in audit.")

    columns = ["Type", "Offset", "Filename", "Extension"]
    truncated = total_rows > row_offset + len(rows)
    columns = [coerce_table_value(col) for col in columns]
    rows = [[coerce_table_value(value) for value in row] for row in rows]

    return {"columns": columns, "rows": rows}, total_rows, truncated


def parse_bulk_extractor_feature(path, row_limit=500, max_bytes=50 * 1024 * 1024, row_offset=0):
    """Parse Bulk Extractor feature file into table data structure."""
    try:
        file_size = os.path.getsize(path)
    except OSError:
        raise ValueError("Unable to read file size.")
    if file_size > max_bytes:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"File is too large for table view ({size_mb:.1f} MB).")

    row_offset = max(0, row_offset)
    row_limit = max(0, row_limit)
    rows = []
    is_histogram = False
    total_rows = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n\r")

                # Skip comments
                if line.startswith("#"):
                    continue
                if not line:
                    continue

                parts = line.split("\t")

                row = None
                # Histogram format: "n=COUNT\tVALUE"
                if parts and parts[0].startswith("n="):
                    is_histogram = True
                    count = parts[0][2:]  # Remove "n=" prefix
                    value = parts[1] if len(parts) > 1 else ""
                    row = [count, value]
                # Standard feature format: "OFFSET\tFEATURE\tCONTEXT"
                elif len(parts) >= 2:
                    file_offset = parts[0]
                    feature = parts[1]
                    context = parts[2] if len(parts) > 2 else ""
                    row = [file_offset, feature, context]
                elif len(parts) == 1 and parts[0]:
                    row = [parts[0], "", ""]

                if row is not None:
                    row_index = total_rows
                    if row_index >= row_offset and len(rows) < row_limit:
                        rows.append(row)
                    total_rows += 1
    except OSError:
        raise ValueError("Unable to read file.")

    if total_rows == 0:
        raise ValueError("No feature data found.")

    if is_histogram:
        columns = ["Count", "Value"]
    else:
        columns = ["Offset", "Feature", "Context"]

    truncated = total_rows > row_offset + len(rows)
    columns = [coerce_table_value(col) for col in columns]
    rows = [[coerce_table_value(value) for value in row] for row in rows]

    return {"columns": columns, "rows": rows}, total_rows, truncated


def detect_text_table_format(path):
    """Detect if a text file can be parsed as a table and return the format type."""
    basename = os.path.basename(path).lower()

    # Foremost/Scalpel audit files
    if basename in ("audit.txt", "foremost.log") or basename.startswith("audit_"):
        return "foremost_audit"

    # Bulk Extractor feature files (common patterns)
    bulk_patterns = [
        "email", "url", "domain", "telephone", "ccn", "ssn", "ip",
        "ether", "exif", "gps", "json", "kml", "rar", "zip", "pdf",
        "winpe", "winlnk", "winprefetch", "httplogs", "wordlist",
        "aes_keys", "facebook", "find", "hex", "pii", "vcard"
    ]

    # Check if it looks like a bulk_extractor output
    for pattern in bulk_patterns:
        if pattern in basename:
            # Verify it's tab-separated or histogram format
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("#"):
                            continue
                        if "\t" in line or line.startswith("n="):
                            return "bulk_extractor"
                        break
            except OSError:
                pass
            break

    # Strings output detection
    if basename == "strings.txt" or basename.endswith("_strings.txt"):
        return "strings"

    # Generic strings detection: check for strings-like output
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            line_count = 0
            offset_count = 0
            for line in f:
                line_count += 1
                if line_count > 20:
                    break
                # Check for hex offset pattern
                if re.match(r"^\s*[0-9a-fA-F]+\s+", line):
                    offset_count += 1

            # If most lines have offsets, it's likely strings output
            if line_count > 0 and offset_count / line_count > 0.7:
                return "strings"
    except OSError:
        pass

    return None


def parse_json_table(path, row_limit=500, max_bytes=10 * 1024 * 1024, row_offset=0):
    try:
        file_size = os.path.getsize(path)
    except OSError:
        raise ValueError("Unable to read file size.")
    if file_size > max_bytes:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"File is too large for table view ({size_mb:.1f} MB).")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        raise ValueError("Unable to read file.")

    if not text.strip():
        raise ValueError("No JSON data found.")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Unable to parse JSON: {exc}") from exc

    columns = []
    rows = []
    if isinstance(data, dict):
        if "columns" in data and "rows" in data:
            columns, rows = build_table_from_rows(data.get("rows") or [], data.get("columns") or [])
        elif "data" in data and isinstance(data["data"], list):
            columns, rows = build_table_from_list(data["data"])
        else:
            columns, rows = build_table_from_list([data])
    elif isinstance(data, list):
        columns, rows = build_table_from_list(data)
    else:
        columns, rows = ["Value"], [[data]]

    row_offset = max(0, row_offset)
    row_limit = max(0, row_limit)
    total_rows = len(rows)
    start = min(row_offset, total_rows)
    end = start + row_limit
    sliced_rows = rows[start:end]
    truncated = total_rows > start + len(sliced_rows)
    columns = [coerce_table_value(col) for col in columns]
    sliced_rows = [[coerce_table_value(value) for value in row] for row in sliced_rows]
    return {"columns": columns, "rows": sliced_rows}, total_rows, truncated


