import hashlib
import json
import logging
import os
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from collections import deque
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template, request, url_for

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")

LOG_LEVEL = os.environ.get("SIFTED_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("sifted")

app = Flask(__name__)
CASES_PATH = os.path.join(DATA_DIR, "cases.json")
RUNS_PATH = os.path.join(DATA_DIR, "runs.json")
VOLATILITY_PLUGINS_PATH = os.path.join(DATA_DIR, "volatility_plugins.json")
RUN_STATE = {}
RUN_STATE_LOCK = threading.Lock()
DATA_LOCK = threading.RLock()
RUN_STATE_TTL_SECONDS = int(os.environ.get("SIFTED_RUN_STATE_TTL_SECONDS", "600"))
RESULT_FILE_LIMIT = int(os.environ.get("SIFTED_RESULT_FILE_LIMIT", "12"))

SECRET_KEY = os.environ.get("SIFTED_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("SIFTED_SECRET_KEY not set; using an ephemeral key.")
app.config["SECRET_KEY"] = SECRET_KEY


def schedule_run_state_cleanup(run_id):
    if RUN_STATE_TTL_SECONDS <= 0:
        return

    def cleanup():
        with RUN_STATE_LOCK:
            state = RUN_STATE.get(run_id)
            if not state or not state.get("done"):
                return
            RUN_STATE.pop(run_id, None)

    timer = threading.Timer(RUN_STATE_TTL_SECONDS, cleanup)
    timer.daemon = True
    timer.start()


def mark_run_done(run_id):
    schedule = False
    with RUN_STATE_LOCK:
        state = RUN_STATE.get(run_id)
        if not state:
            return
        state["done"] = True
        if not state.get("cleanup_scheduled"):
            state["cleanup_scheduled"] = True
            schedule = True
    if schedule:
        schedule_run_state_cleanup(run_id)


def normalize_path(path):
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def parse_path_list(raw_value, default):
    if raw_value is None:
        items = default
    elif isinstance(raw_value, str):
        items = [item.strip() for item in raw_value.split(",")]
    else:
        items = list(raw_value)

    cleaned = []
    for item in items:
        if not item:
            continue
        cleaned.append(normalize_path(item))
    return cleaned


ALLOWED_PATHS = parse_path_list(os.environ.get("SIFTED_ALLOWED_PATHS"), ["/cases"])
OUTPUT_ROOTS = parse_path_list(os.environ.get("SIFTED_OUTPUT_ROOTS"), ["/cases"])
INPUT_ROOTS = parse_path_list(os.environ.get("SIFTED_INPUT_ROOTS"), [])
SYMBOL_ROOTS = parse_path_list(os.environ.get("SIFTED_SYMBOL_ROOTS"), [])


def shell_join(command):
    try:
        return shlex.join(command)
    except AttributeError:
        return " ".join(shlex.quote(part) for part in command)


def is_path_allowed(path, allowed_roots):
    if not allowed_roots:
        return True
    target = normalize_path(path)
    for root in allowed_roots:
        try:
            if os.path.commonpath([target, root]) == root:
                return True
        except ValueError:
            continue
    return False


def normalize_output_path(output_path):
    normalized = normalize_path(output_path)
    if not is_path_allowed(normalized, OUTPUT_ROOTS):
        return "", "Output path is outside the allowed roots."
    return normalized, ""


def validate_input_path(raw_path, label, allowed_roots):
    if not raw_path:
        return "", f"{label} path is required."
    normalized = normalize_path(raw_path)
    if allowed_roots and not is_path_allowed(normalized, allowed_roots):
        return "", f"{label} path is outside the allowed roots."
    if not os.path.exists(normalized):
        return "", f"{label} path not found."
    return normalized, ""


# --- Refactored Helper Functions ---


def error_response(message, status=400):
    """Create a standardized JSON error response."""
    return jsonify({"error": message}), status


def extract_run_payload(payload, required_keys=None):
    """
    Extract and validate common fields from a run request payload.
    Returns (extracted_data, error_message) tuple.
    """
    extracted = {
        "image_path": payload.get("image_path", "").strip(),
        "output_path": payload.get("output_path", "").strip(),
        "case_id": payload.get("case_id") or None,
    }

    if required_keys:
        for key in required_keys:
            if key == "image_path" and not extracted["image_path"]:
                return None, "Image path is required."
            if key == "source_path":
                extracted["source_path"] = payload.get("source_path", "").strip()
                if not extracted["source_path"]:
                    return None, "Source path is required."

    return extracted, ""


def validate_output_folder(output_path, must_be_empty=True, must_not_exist=False):
    """
    Validate output folder constraints.
    Returns error message string, or empty string if valid.
    """
    if must_not_exist and os.path.exists(output_path):
        return "Output folder must not exist."
    if os.path.exists(output_path) and not os.path.isdir(output_path):
        return "Output path must be a folder."
    if must_be_empty and os.path.isdir(output_path) and os.listdir(output_path):
        return "Output folder must be empty."
    return ""


def ensure_output_folder(output_path, create_parent_only=False):
    """
    Create output folder (or its parent).
    Returns error message string, or empty string if successful.
    """
    try:
        target = os.path.dirname(output_path) if create_parent_only else output_path
        os.makedirs(target, exist_ok=True)
        return ""
    except OSError:
        return "Unable to create output folder."


def update_run_status(run_id, updates):
    """
    Update a run record with the given field updates.
    Updates are applied in-place and saved atomically.
    """
    with DATA_LOCK:
        runs = load_runs()
        for run in runs:
            if run.get("id") == run_id:
                run.update(updates)
                break
        save_runs(runs)


def init_run_state(run_id):
    """
    Initialize run state with event queue for a new run.
    Returns (event_queue, emit_function) tuple.
    """
    event_queue = queue.Queue()
    with RUN_STATE_LOCK:
        RUN_STATE[run_id] = {
            "queue": event_queue,
            "done": False,
        }

    def emit(event_type, message):
        payload = {"type": event_type, "message": message}
        event_queue.put(payload)

    return event_queue, emit


def finalize_run(run_id, status, exit_code, log_path, extra_updates=None):
    """
    Finalize a run by emitting done event and updating run record.
    """
    updates = {
        "status": status,
        "exit_code": exit_code,
        "log_path": log_path,
    }
    if extra_updates:
        updates.update(extra_updates)
    update_run_status(run_id, updates)


def run_completion_message(status):
    """Return standard run completion message based on status."""
    return "Run completed." if status == "success" else "Run completed with errors."


EZ_TOOL_ORDER = [
    "amcacheparser",
    "appcompatcacheparser",
    "lecmd",
    "jlecmd",
    "sbecmd",
    "rbcmd",
    "recentfilecacheparser",
    "evtxecmd",
    "mftecmd",
    "recmd",
    "sqlecmd",
]

EZ_TOOL_CATALOG = {
    "amcacheparser": {
        "label": "AmcacheParser",
        "summary": "Program presence (Amcache.hve)",
        "description": "Parses Amcache.hve to list installed or executed programs with hashes and timestamps.",
        "input_hint": "Source: Amcache.hve file",
        "input_mode": "file",
        "csv_name": "amcache.csv",
        "binaries": ["AmcacheParser", "amcacheparser"],
        "curated": True,
        "category": "program-execution",
    },
    "lecmd": {
        "label": "LECmd",
        "summary": "LNK shortcut activity",
        "description": "Parses .lnk shortcut files to reveal target paths, volume data, and timestamps.",
        "input_hint": "Source: LNK file or directory",
        "input_mode": "file_or_dir",
        "csv_name": "lnk.csv",
        "binaries": ["LECmd", "lecmd"],
        "curated": True,
        "category": "user-activity",
    },
    "jlecmd": {
        "label": "JLECmd",
        "summary": "Jump List usage",
        "description": "Parses Jump List files to show recent file usage and app activity.",
        "input_hint": "Source: Jump List file or directory",
        "input_mode": "file_or_dir",
        "csv_name": "jumplist.csv",
        "binaries": ["JLECmd", "jlecmd"],
        "curated": True,
        "category": "user-activity",
    },
    "evtxecmd": {
        "label": "EvtxECmd",
        "summary": "Windows Event Logs",
        "description": "Parses EVTX event logs into CSV for timeline and alert review.",
        "input_hint": "Source: EVTX file or directory",
        "input_mode": "file_or_dir",
        "csv_name": "eventlogs.csv",
        "binaries": ["EvtxECmd", "evtxecmd"],
        "curated": True,
        "category": "system-events",
    },
    "mftecmd": {
        "label": "MFTECmd",
        "summary": "MFT and USN activity",
        "description": "Parses the NTFS $MFT (and optionally $UsnJrnl) for file activity timelines.",
        "input_hint": "Source: $MFT file",
        "input_mode": "file",
        "csv_name": "mft.csv",
        "binaries": ["MFTECmd", "mftecmd"],
        "curated": True,
        "category": "file-system",
    },
    "appcompatcacheparser": {
        "label": "AppCompatCacheParser",
        "summary": "ShimCache execution evidence",
        "description": "Parses the Application Compatibility Cache (ShimCache) from the SYSTEM registry hive to show programs that have executed.",
        "input_hint": "Source: SYSTEM registry hive",
        "input_mode": "file",
        "csv_name": "shimcache.csv",
        "binaries": ["AppCompatCacheParser", "appcompatcacheparser"],
        "curated": True,
        "category": "program-execution",
    },
    "sbecmd": {
        "label": "SBECmd",
        "summary": "ShellBags folder history",
        "description": "Parses ShellBags from NTUSER.DAT and UsrClass.dat to reveal folder access history, including deleted folders and network shares.",
        "input_hint": "Source: Directory containing registry hives (NTUSER.DAT, UsrClass.dat)",
        "input_mode": "dir",
        "csv_name": "shellbags.csv",
        "binaries": ["SBECmd", "sbecmd"],
        "curated": True,
        "category": "user-activity",
    },
    "rbcmd": {
        "label": "RBCmd",
        "summary": "Recycle Bin contents",
        "description": "Parses Recycle Bin $I files to show deleted file metadata including original path, deletion time, and file size.",
        "input_hint": "Source: $Recycle.Bin folder or $I file",
        "input_mode": "file_or_dir",
        "csv_name": "recyclebin.csv",
        "binaries": ["RBCmd", "rbcmd"],
        "curated": True,
        "category": "user-activity",
    },
    "recentfilecacheparser": {
        "label": "RecentFileCacheParser",
        "summary": "RecentFileCache.bcf parsing",
        "description": "Parses RecentFileCache.bcf to list recently executed programs. Present on Windows 7/Server 2008 R2 systems.",
        "input_hint": "Source: RecentFileCache.bcf file",
        "input_mode": "file",
        "csv_name": "recentfilecache.csv",
        "binaries": ["RecentFileCacheParser", "recentfilecacheparser"],
        "curated": False,
        "category": "program-execution",
    },
    "recmd": {
        "label": "RECmd",
        "summary": "Registry analysis",
        "description": "Parses Windows registry hives using the RegistryASEPs batch file to extract Run keys, services, scheduled tasks, and other persistence mechanisms.",
        "input_hint": "Source: Directory containing registry hives (SYSTEM, SOFTWARE, NTUSER.DAT)",
        "input_mode": "dir",
        "csv_name": "registry.csv",
        "binaries": ["RECmd", "recmd"],
        "curated": True,
        "category": "persistence",
        "batch_file": "/opt/zimmermantools/RECmd/BatchExamples/RegistryASEPs.reb",
    },
    "sqlecmd": {
        "label": "SQLECmd",
        "summary": "SQLite database parsing",
        "description": "Parses SQLite databases using predefined maps. Supports browser history, cookies, downloads, and other SQLite-based artifacts.",
        "input_hint": "Source: SQLite database file or directory",
        "input_mode": "file_or_dir",
        "csv_name": "sqlite.csv",
        "binaries": ["SQLECmd", "sqlecmd"],
        "curated": True,
        "category": "browser-network",
        "supports_csvf": False,
    },
}


def resolve_ez_tool(tool_id):
    tool = EZ_TOOL_CATALOG.get(tool_id)
    if not tool:
        return None
    binary_path = None
    binary_display = tool["binaries"][0]
    for candidate in tool["binaries"]:
        candidate_path = shutil.which(candidate)
        if candidate_path:
            binary_path = candidate_path
            binary_display = candidate
            break
    return {
        **tool,
        "id": tool_id,
        "installed": bool(binary_path),
        "binary": binary_path,
        "binary_display": binary_display,
    }


def build_ez_command(tool, source_path, output_path):
    input_mode = tool["input_mode"]
    if input_mode == "dir":
        input_flag = "-d"
    elif input_mode == "file":
        input_flag = "-f"
    else:
        input_flag = "-d" if os.path.isdir(source_path) else "-f"
    binary = tool["binary"] or tool["binary_display"]
    command = [
        binary,
        input_flag,
        source_path,
        "--csv",
        output_path,
    ]
    # Add batch file for RECmd
    if tool.get("batch_file"):
        command.extend(["--bn", tool["batch_file"]])
    # Add custom output filename if supported
    if tool.get("supports_csvf", True):
        command.extend(["--csvf", tool["csv_name"]])
    return command

LINUX_TRIAGE_BUNDLES = [
    {
        "id": "linux-process",
        "label": "Process + Tasking",
        "description": "Process listings, scans, and thread context.",
        "plugins": [
            "linux.pslist",
            "linux.pstree",
            "linux.psscan",
            "linux.psaux",
            "linux.proc",
            "linux.pidhashtable",
            "linux.pscallstack",
            "linux.kthreads",
        ],
    },
    {
        "id": "linux-network",
        "label": "Network",
        "description": "Sockets, interfaces, and netfilter state.",
        "plugins": [
            "linux.ip",
            "linux.sockstat",
            "linux.sockscan",
            "linux.netfilter",
        ],
    },
    {
        "id": "linux-filesystem",
        "label": "Filesystem",
        "description": "Open files, mounts, and cached file data.",
        "plugins": [
            "linux.lsof",
            "linux.mountinfo",
            "linux.pagecache",
            "linux.library_list",
            "linux.elfs",
        ],
    },
    {
        "id": "linux-persistence",
        "label": "Persistence",
        "description": "Userland indicators and runtime hooks.",
        "plugins": [
            "linux.bash",
            "linux.envars",
            "linux.tty_check",
            "linux.keyboard_notifiers",
            "linux.tracing.ftrace",
            "linux.tracing.tracepoints",
            "linux.tracing.perf_events",
        ],
    },
    {
        "id": "linux-kernel",
        "label": "Kernel + Drivers",
        "description": "Modules, syscall checks, and kernel metadata.",
        "plugins": [
            "linux.lsmod",
            "linux.kallsyms",
            "linux.hidden_modules",
            "linux.modxview",
            "linux.check_modules",
            "linux.check_syscall",
            "linux.check_idt",
            "linux.iomem",
            "linux.module_extract",
            "linux.kmsg",
        ],
    },
    {
        "id": "linux-user",
        "label": "User Activity",
        "description": "Shell history, env vars, and session artifacts.",
        "plugins": [
            "linux.bash",
            "linux.psaux",
            "linux.lsof",
            "linux.envars",
            "linux.tty_check",
            "linux.proc",
        ],
    },
]

WINDOWS_TRIAGE_BUNDLES = [
    {
        "id": "windows-triage",
        "label": "Core Triage",
        "description": "Processes, network, sessions, and quick context.",
        "plugins": [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.psscan",
            "windows.cmdline",
            "windows.dlllist",
            "windows.handles",
            "windows.netscan",
            "windows.netstat",
            "windows.sessions",
            "windows.envars",
        ],
    },
    {
        "id": "windows-malware",
        "label": "Malware + Evasion",
        "description": "Hollowing, hooks, and stealth indicators.",
        "plugins": [
            "windows.malfind",
            "windows.malware.malfind",
            "windows.psxview",
            "windows.malware.psxview",
            "windows.suspicious_threads",
            "windows.malware.suspicious_threads",
            "windows.hollowprocesses",
            "windows.malware.hollowprocesses",
            "windows.processghosting",
            "windows.malware.processghosting",
            "windows.direct_system_calls",
            "windows.indirect_system_calls",
            "windows.unhooked_system_calls",
            "windows.malware.direct_system_calls",
            "windows.malware.indirect_system_calls",
            "windows.malware.unhooked_system_calls",
            "windows.skeleton_key_check",
            "windows.malware.skeleton_key_check",
            "windows.ldrmodules",
            "windows.malware.ldrmodules",
            "windows.drivermodule",
            "windows.malware.drivermodule",
            "windows.pe_symbols",
            "windows.etwpatch",
        ],
    },
    {
        "id": "windows-services",
        "label": "Services + Drivers",
        "description": "Services, drivers, and device inventory.",
        "plugins": [
            "windows.svcscan",
            "windows.svclist",
            "windows.svcdiff",
            "windows.malware.svcdiff",
            "windows.getservicesids",
            "windows.driverscan",
            "windows.modscan",
            "windows.modules",
            "windows.driverirp",
            "windows.devicetree",
            "windows.unloadedmodules",
        ],
    },
    {
        "id": "windows-registry",
        "label": "Registry + User",
        "description": "Hives, user activity, and credential artifacts.",
        "plugins": [
            "windows.registry.hivelist",
            "windows.registry.hivescan",
            "windows.registry.printkey",
            "windows.registry.userassist",
            "windows.registry.amcache",
            "windows.registry.scheduled_tasks",
            "windows.registry.certificates",
            "windows.registry.cachedump",
            "windows.registry.hashdump",
            "windows.registry.lsadump",
            "windows.registry.getcellroutine",
            "windows.amcache",
            "windows.scheduled_tasks",
            "windows.cachedump",
            "windows.hashdump",
            "windows.lsadump",
            "windows.getsids",
            "windows.privileges",
        ],
    },
    {
        "id": "windows-artifacts",
        "label": "Files + Memory Artifacts",
        "description": "Filesystem, memory regions, and UI artifacts.",
        "plugins": [
            "windows.filescan",
            "windows.mftscan",
            "windows.dumpfiles",
            "windows.memmap",
            "windows.vadinfo",
            "windows.vadwalk",
            "windows.vadregexscan",
            "windows.vadyarascan",
            "windows.strings",
            "windows.pedump",
            "windows.truecrypt",
            "windows.consoles",
            "windows.deskscan",
            "windows.desktops",
            "windows.windowstations",
            "windows.timers",
            "windows.mutantscan",
            "windows.symlinkscan",
            "windows.bigpools",
            "windows.poolscanner",
            "windows.kpcrs",
            "windows.crashinfo",
            "windows.debugregisters",
        ],
    },
]

WINDOWS_DEFAULT_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.netscan",
]


def load_volatility_plugins():
    if not os.path.exists(VOLATILITY_PLUGINS_PATH):
        return {"windows": [], "linux": [], "mac": []}
    try:
        with open(VOLATILITY_PLUGINS_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        logger.warning("Unable to load volatility plugins from %s", VOLATILITY_PLUGINS_PATH)
        return {"windows": [], "linux": [], "mac": []}
    return {
        "windows": data.get("windows", []),
        "linux": data.get("linux", []),
        "mac": data.get("mac", []),
    }


def slugify(value):
    cleaned = "".join(char if char.isalnum() else "-" for char in value.lower())
    return "-".join(filter(None, cleaned.split("-"))) or "case"


def detect_volatility_symbol_path():
    candidates = [
        os.path.join(os.path.dirname(__file__), "volatility3", "volatility3", "symbols"),
        os.path.join(os.path.dirname(__file__), "volatility3", "symbols"),
        "/home/sansforensics/Temp/Windows-Symbol-Tables/symbols",
        os.path.expanduser("~/.volx/cache/volatility3/symbols"),
        os.path.expanduser("~/.cache/volatility3/symbols"),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    return ""


def load_cases():
    if not os.path.exists(CASES_PATH):
        return []
    try:
        with DATA_LOCK, open(CASES_PATH, "r", encoding="utf-8") as handle:
            cases = json.load(handle)
    except (OSError, json.JSONDecodeError):
        logger.warning("Unable to load cases from %s", CASES_PATH)
        return []

    updated = False
    for case in cases:
        if not case.get("slug"):
            base = case.get("image_path") or case.get("name", "case")
            case["slug"] = slugify(os.path.basename(base))
            updated = True

    if updated:
        save_cases(cases)

    return cases


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


def parse_csv_table(path, row_limit=500, max_bytes=10 * 1024 * 1024, row_offset=0):
    """Parse a CSV file into table data structure."""
    try:
        file_size = os.path.getsize(path)
    except OSError:
        raise ValueError("Unable to read file size.")
    if file_size > max_bytes:
        size_mb = file_size / (1024 * 1024)
        raise ValueError(f"File is too large for table view ({size_mb:.1f} MB).")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            import csv
            reader = csv.reader(handle)
            rows_data = list(reader)
    except OSError:
        raise ValueError("Unable to read file.")

    if not rows_data:
        raise ValueError("No CSV data found.")

    columns = rows_data[0] if rows_data else []
    rows = rows_data[1:] if len(rows_data) > 1 else []

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

    stripped = text.lstrip()
    if stripped and stripped[0] not in "[{":
        bracket_indices = [idx for idx in (text.find("{"), text.find("[")) if idx != -1]
        if not bracket_indices:
            raise ValueError("No JSON data found.")
        text = text[min(bracket_indices) :]

    decoder = json.JSONDecoder()
    try:
        data, _ = decoder.raw_decode(text.lstrip())
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


def list_directory_files(directory, limit=RESULT_FILE_LIMIT):
    if limit is not None and limit <= 0:
        return [], False
    if not directory or not os.path.isdir(directory):
        return [], False
    normalized = normalize_path(directory)
    if not is_path_allowed(normalized, OUTPUT_ROOTS):
        return [], False
    files = []
    truncated = False
    try:
        with os.scandir(normalized) as it:
            for entry in it:
                if not entry.is_file():
                    continue
                if not is_path_allowed(entry.path, OUTPUT_ROOTS):
                    continue
                files.append({"name": entry.name, "path": entry.path})
                if limit is not None and len(files) > limit:
                    truncated = True
                    break
    except OSError:
        return [], False
    files.sort(key=lambda item: item["name"].lower())
    if limit is not None:
        return files[:limit], truncated
    return files, truncated


def list_result_files(output_path, limit=RESULT_FILE_LIMIT):
    results_dir = os.path.join(output_path, "results")
    return list_directory_files(results_dir, limit=limit)


def build_run_manifest(run, limit=RESULT_FILE_LIMIT):
    files = []
    truncated = False
    seen = set()

    def add_file(path, label=None):
        if not path:
            return
        normalized = normalize_path(path)
        if not is_path_allowed(normalized, OUTPUT_ROOTS):
            return
        if not os.path.isfile(normalized):
            return
        if normalized in seen:
            return
        seen.add(normalized)
        files.append({"name": label or os.path.basename(normalized), "path": normalized})

    def add_list(items, was_truncated):
        nonlocal truncated
        if was_truncated:
            truncated = True
        for item in items:
            path = item.get("path")
            if not path:
                continue
            if path in seen:
                continue
            seen.add(path)
            files.append(item)

    add_file(run.get("output_file"))
    add_file(run.get("timeline_path"))
    add_file(run.get("storage_path"))

    output_path = run.get("output_path") or ""
    if output_path:
        remaining = None if limit is None else max(0, limit - len(files))
        if run.get("tool") == "volatility" and (remaining is None or remaining):
            result_files, result_truncated = list_result_files(output_path, limit=remaining)
            add_list(result_files, result_truncated)
            remaining = None if limit is None else max(0, limit - len(files))
        if remaining is None or remaining:
            root_files, root_truncated = list_directory_files(output_path, limit=remaining)
            add_list(root_files, root_truncated)

    if limit is not None and len(files) > limit:
        truncated = True
        files = files[:limit]

    return files, truncated


def save_cases(cases):
    with DATA_LOCK:
        write_json_atomic(CASES_PATH, cases)


def compute_sha256(path):
    hash_obj = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def load_runs():
    if not os.path.exists(RUNS_PATH):
        return []
    try:
        with DATA_LOCK, open(RUNS_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        logger.warning("Unable to load runs from %s", RUNS_PATH)
        return []


def save_runs(runs):
    with DATA_LOCK:
        write_json_atomic(RUNS_PATH, runs)


def default_output_path(case_slug, tool):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return os.path.join("/cases", case_slug, tool, timestamp)


def resolve_case_slug(case_id):
    if not case_id:
        return ""
    for case in load_cases():
        if case.get("id") == case_id:
            return case.get("slug", case_id)
    return case_id


def resolve_output_path(output_path, case_id, tool):
    if case_id and not output_path:
        case_slug = resolve_case_slug(case_id)
        output_path = default_output_path(case_slug, tool)
    if not output_path:
        return "", "Output folder is required."
    normalized, output_error = normalize_output_path(output_path)
    if output_error:
        return "", output_error
    return normalized, ""


def create_run_record(tool, case_id, image_path, output_path, command_text, extra=None):
    run_id = uuid.uuid4().hex
    log_path = f"{output_path}.log"
    try:
        with open(log_path, "a", encoding="utf-8"):
            pass
    except OSError:
        return None, "Unable to create log file."

    run = {
        "id": run_id,
        "tool": tool,
        "case_id": case_id,
        "image_path": image_path,
        "output_path": output_path,
        "command": command_text,
        "log_path": log_path,
        "status": "running",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        run.update(extra)

    with DATA_LOCK:
        runs = load_runs()
        runs.append(run)
        save_runs(runs)

    return run, ""


def write_json_atomic(path, payload):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, delete=False
        ) as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
            temp_file = handle.name
        os.replace(temp_file, path)
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass


def build_foremost_command(
    image_path, output_path, types, quick, verbose, config_path=None, allow_existing=False
):
    args = ["foremost", "-i", image_path, "-o", output_path]
    if types:
        args.extend(["-t", ",".join(types)])
    if config_path:
        args.extend(["-c", config_path])
    if quick:
        args.append("-q")
    if verbose:
        args.append("-v")
    if allow_existing:
        args.append("-T")
    return args


TYPE_MAP = {"jpeg": "jpg", "tiff": "tif"}
CONFIG_LINE_RE = re.compile(r"^\s*#?\s*([a-z0-9]+)\s+[yn]\s+\d+", re.IGNORECASE)


def sanitize_types(raw_types):
    clean = []
    for entry in raw_types:
        value = "".join(char for char in str(entry) if char.isalnum()).lower()
        if not value:
            continue
        value = TYPE_MAP.get(value, value)
        clean.append(value)
    return clean


def build_config_for_types(types):
    if not types:
        return None
    try:
        with open("/etc/foremost.conf", "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return None

    selected = []
    for line in lines:
        match = CONFIG_LINE_RE.match(line)
        if not match:
            continue
        ext = match.group(1).lower()
        if ext in types:
            if ext == "jpg":
                # Keep stricter JPG signatures, skip the overly broad \xff\xd8 rule.
                if "\\xff\\xd8\\xff\\xe0" not in line and "\\xff\\xd8\\xff\\xe1" not in line:
                    continue
            selected.append(line.lstrip("#").strip())

    if not selected:
        return None

    config_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", prefix="sifted-foremost-", delete=False
    )
    with config_file as handle:
        handle.write("# SIFTed generated config\n")
        for entry in selected:
            handle.write(f"{entry}\n")

    return config_file.name


def build_scalpel_config_for_types(types):
    if not types:
        return None, types
    try:
        with open("/etc/scalpel/scalpel.conf", "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return None, types

    entries = {}
    for line in lines:
        match = CONFIG_LINE_RE.match(line)
        if not match:
            continue
        ext = match.group(1).lower()
        entries.setdefault(ext, []).append(line.lstrip("#").strip())

    missing = [ext for ext in types if ext not in entries]
    if missing:
        return None, missing

    selected = []
    for ext in types:
        selected.extend(entries.get(ext, []))

    if not selected:
        return None, types

    config_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", prefix="sifted-scalpel-", delete=False
    )
    with config_file as handle:
        handle.write("# SIFTed generated config\n")
        for entry in selected:
            handle.write(f"{entry}\n")

    return config_file.name, []


def build_volatility_commands(image_path, output_path, symbol_path, plugins, renderer):
    vol_script = os.path.join(os.path.dirname(__file__), "volatility3", "vol.py")
    base = [
        sys.executable,
        vol_script,
        "--offline",
        "-q",
        "-f",
        image_path,
        "-o",
        output_path,
    ]
    if symbol_path:
        base.extend(["-s", symbol_path])
    if renderer:
        base.extend(["-r", renderer])

    commands = []
    for plugin in plugins:
        commands.append(base + [plugin])
    return commands


def build_plaso_commands(image_path, output_path, timezone):
    storage_path = os.path.join(output_path, "timeline.plaso")
    timeline_path = os.path.join(output_path, "timeline.csv")
    log2timeline_cmd = ["log2timeline.py", "--storage_file", storage_path, image_path]
    psort_cmd = [
        "psort.py",
        "-o",
        "l2tcsv",
        "-w",
        timeline_path,
        "--output_time_zone",
        timezone,
        storage_path,
    ]
    return log2timeline_cmd, psort_cmd, storage_path, timeline_path


FILE_LINE_RE = re.compile(r"^\s*\d+:\s+(\S+)")


def extract_extension(filename):
    if "." not in filename:
        return "unknown"
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext or "unknown"


def summarize_counts(counts, limit=6):
    if not counts:
        return ""
    items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    shown = items[:limit]
    summary = " | ".join(f"{ext}: {count}" for ext, count in shown)
    if len(items) > limit:
        summary = f"{summary} (+{len(items) - limit} more)"
    return summary


def read_head_tail(path, head_size=64, tail_size=2048):
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        head = handle.read(head_size)
        if size <= tail_size:
            handle.seek(0)
            tail = handle.read()
        else:
            handle.seek(-tail_size, os.SEEK_END)
            tail = handle.read()
    return head, tail


def validate_png(path):
    head, tail = read_head_tail(path)
    if not head.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    return tail.endswith(b"\x00\x00\x00\x00IEND\xaeB`\x82")


def validate_jpeg(path):
    head, tail = read_head_tail(path)
    return head.startswith(b"\xff\xd8") and tail.endswith(b"\xff\xd9")


def validate_gif(path):
    head, tail = read_head_tail(path)
    return head.startswith((b"GIF87a", b"GIF89a")) and tail.endswith(b"\x3b")


def validate_pdf(path):
    head, tail = read_head_tail(path)
    if not head.startswith(b"%PDF"):
        return False
    return b"%%EOF" in tail


def validate_zip(path):
    head, tail = read_head_tail(path)
    if not head.startswith(b"PK\x03\x04"):
        return False
    return b"PK\x05\x06" in tail


def validate_bmp(path):
    head, _ = read_head_tail(path, head_size=2, tail_size=2)
    return head.startswith(b"BM")


def validate_tiff(path):
    head, _ = read_head_tail(path, head_size=4, tail_size=4)
    return head.startswith(b"II*\x00") or head.startswith(b"MM\x00*")


def validate_ole(path):
    head, _ = read_head_tail(path, head_size=8, tail_size=8)
    return head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")


def validate_rtf(path):
    head, _ = read_head_tail(path, head_size=5, tail_size=5)
    return head.startswith(b"{\\rtf")


def validate_pe(path):
    try:
        with open(path, "rb") as handle:
            mz = handle.read(64)
            if not mz.startswith(b"MZ"):
                return False
            if len(mz) < 64:
                return False
            pe_offset = int.from_bytes(mz[0x3C:0x40], "little", signed=False)
            handle.seek(pe_offset)
            return handle.read(4) == b"PE\x00\x00"
    except OSError:
        return False


VALIDATORS = {
    "jpg": validate_jpeg,
    "jpeg": validate_jpeg,
    "png": validate_png,
    "gif": validate_gif,
    "pdf": validate_pdf,
    "zip": validate_zip,
    "bmp": validate_bmp,
    "tif": validate_tiff,
    "tiff": validate_tiff,
    "doc": validate_ole,
    "xls": validate_ole,
    "ppt": validate_ole,
    "rtf": validate_rtf,
    "exe": validate_pe,
    "dll": validate_pe,
}


def validate_foremost_output(output_path):
    rejects_dir = os.path.join(output_path, "rejects")
    os.makedirs(rejects_dir, exist_ok=True)
    kept = 0
    rejected = 0

    for root, _, files in os.walk(output_path):
        if root.startswith(rejects_dir):
            continue
        if root.startswith(os.path.join(output_path, "duplicates")):
            continue
        for filename in files:
            if root == output_path and filename in {"audit.txt", "foremost.log"}:
                continue
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            validator = VALIDATORS.get(ext)
            if not validator:
                continue
            src = os.path.join(root, filename)
            is_valid = False
            try:
                is_valid = validator(src)
            except OSError:
                is_valid = False
            if is_valid:
                kept += 1
                continue
            rel = os.path.relpath(src, output_path)
            dest = os.path.join(rejects_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.exists(dest):
                base, ext_part = os.path.splitext(dest)
                counter = 1
                while os.path.exists(dest):
                    dest = f"{base}_{counter}{ext_part}"
                    counter += 1
            try:
                os.rename(src, dest)
                rejected += 1
            except OSError:
                continue
    return kept, rejected


def dedup_foremost_output(output_path):
    duplicates_dir = os.path.join(output_path, "duplicates")
    rejects_dir = os.path.join(output_path, "rejects")
    os.makedirs(duplicates_dir, exist_ok=True)
    seen = {}
    moved = 0
    skipped = 0

    for root, _, files in os.walk(output_path):
        if root.startswith(duplicates_dir):
            continue
        if root.startswith(rejects_dir):
            continue
        for filename in files:
            if root == output_path and filename in {"audit.txt", "foremost.log"}:
                continue
            src = os.path.join(root, filename)
            try:
                with open(src, "rb") as handle:
                    digest = hashlib.md5(handle.read()).hexdigest()
            except OSError:
                skipped += 1
                continue
            if digest in seen:
                rel = os.path.relpath(src, output_path)
                dest = os.path.join(duplicates_dir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if os.path.exists(dest):
                    base, ext = os.path.splitext(dest)
                    counter = 1
                    while os.path.exists(dest):
                        dest = f"{base}_{counter}{ext}"
                        counter += 1
                try:
                    os.rename(src, dest)
                    moved += 1
                except OSError:
                    skipped += 1
                continue
            seen[digest] = src
    return moved, skipped


def parse_audit_counts(audit_path):
    counts = {}
    if not audit_path or not os.path.exists(audit_path):
        return counts
    with open(audit_path, "r", encoding="utf-8") as handle:
        for line in handle:
            match = FILE_LINE_RE.match(line)
            if not match:
                continue
            filename = match.group(1)
            ext = extract_extension(filename)
            counts[ext] = counts.get(ext, 0) + 1
    return counts




def start_foremost_run(run_id, command, log_path, output_path, config_path=None):
    event_queue, emit = init_run_state(run_id)

    def runner():
        emit("status", "Running Foremost...")
        counts = {}
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                while True:
                    line = process.stdout.readline() if process.stdout else ""
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    log_file.write(line)
                    log_file.flush()

                    match = FILE_LINE_RE.match(line)
                    if match:
                        filename = match.group(1)
                        ext = extract_extension(filename)
                        counts[ext] = counts.get(ext, 0) + 1

                exit_code = process.poll() or 0
        except FileNotFoundError:
            emit("error", "Foremost is not installed or not on PATH.")
            exit_code = 127
        except OSError:
            emit("error", "Unable to run Foremost.")
            exit_code = 1
        finally:
            if config_path:
                try:
                    os.remove(config_path)
                except OSError:
                    pass

        status = "success" if exit_code == 0 else "error"
        audit_path = os.path.join(output_path, "audit.txt")
        audit_counts = parse_audit_counts(audit_path)
        final_counts = audit_counts or counts
        summary = summarize_counts(final_counts)
        if summary:
            emit("milestone", f"Final counts: {summary}")
        kept, rejected = validate_foremost_output(output_path)
        if rejected:
            emit("milestone", f"Validation: {rejected} moved to rejects.")
        moved, skipped = dedup_foremost_output(output_path)
        if moved:
            emit("milestone", f"De-dup complete: {moved} moved to duplicates.")
        if skipped:
            emit("milestone", f"De-dup skipped: {skipped} files.")
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        finalize_run(run_id, status, exit_code, log_path, {"summary": summary})

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    return event_queue


def start_foremost_safe_run(
    run_id, image_path, output_path, types, quick, verbose, log_path, timeout_seconds
):
    event_queue, emit = init_run_state(run_id)

    def runner():
        emit("status", "Running Foremost (safe mode)...")
        counts = {}
        audit_counts = {}
        had_errors = False
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                for carve_type in types:
                    config_path = build_config_for_types([carve_type])
                    if not config_path:
                        emit("error", f"Unsupported type: {carve_type}.")
                        had_errors = True
                        continue
                    command = build_foremost_command(
                        image_path,
                        output_path,
                        [carve_type],
                        quick,
                        verbose,
                        config_path=config_path,
                        allow_existing=True,
                    )
                    emit("milestone", f"Running {carve_type} (10s cap)")
                    log_file.write(f"\n--- {carve_type} ---\n")
                    log_file.flush()
                    timed_out = False
                    try:
                        process = subprocess.Popen(
                            command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                        try:
                            output, _ = process.communicate(timeout=timeout_seconds)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            timed_out = True
                            output, _ = process.communicate()
                        log_file.write(output or "")
                        log_file.flush()
                        for line in (output or "").splitlines():
                            match = FILE_LINE_RE.match(line)
                            if match:
                                filename = match.group(1)
                                ext = extract_extension(filename)
                                counts[ext] = counts.get(ext, 0) + 1
                        exit_code = process.returncode or 0
                    except OSError:
                        emit("error", f"Unable to run {carve_type}.")
                        exit_code = 1

                    if timed_out:
                        emit("error", f"{carve_type} timed out after {timeout_seconds}s.")
                        had_errors = True
                    elif exit_code != 0:
                        emit("error", f"{carve_type} exited with errors.")
                        had_errors = True

                    audit_path = os.path.join(output_path, "audit.txt")
                    if os.path.exists(audit_path):
                        dest = os.path.join(output_path, f"audit_{carve_type}.txt")
                        try:
                            os.replace(audit_path, dest)
                        except OSError:
                            dest = audit_path
                        parsed = parse_audit_counts(dest)
                        for ext, count in parsed.items():
                            audit_counts[ext] = audit_counts.get(ext, 0) + count

                    try:
                        os.remove(config_path)
                    except OSError:
                        pass
        except FileNotFoundError:
            emit("error", "Foremost is not installed or not on PATH.")
            had_errors = True
        except OSError:
            emit("error", "Unable to run Foremost.")
            had_errors = True

        final_counts = audit_counts or counts
        summary = summarize_counts(final_counts)
        if summary:
            emit("milestone", f"Final counts: {summary}")
        kept, rejected = validate_foremost_output(output_path)
        if rejected:
            emit("milestone", f"Validation: {rejected} moved to rejects.")
        moved, skipped = dedup_foremost_output(output_path)
        if moved:
            emit("milestone", f"De-dup complete: {moved} moved to duplicates.")
        if skipped:
            emit("milestone", f"De-dup skipped: {skipped} files.")

        status = "error" if had_errors else "success"
        exit_code = 1 if had_errors else 0
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        finalize_run(run_id, status, exit_code, log_path, {"summary": summary})

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    return event_queue


def start_generic_run(run_id, command, log_path, post_process=None):
    event_queue, emit = init_run_state(run_id)

    def runner():
        emit("status", "Running...")
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in process.stdout or []:
                    log_file.write(line)
                    log_file.flush()
                exit_code = process.wait() or 0
        except FileNotFoundError:
            emit("error", "Tool is not installed or not on PATH.")
            exit_code = 127
        except OSError:
            emit("error", "Unable to run tool.")
            exit_code = 1

        status = "success" if exit_code == 0 else "error"
        post_summary = None
        if post_process:
            try:
                post_summary = post_process()
                if post_summary:
                    with open(log_path, "a", encoding="utf-8") as log_file:
                        log_file.write(f"\nPost-process: {post_summary}\n")
            except Exception:
                emit("error", "Post-processing failed.")
                status = "error"
                exit_code = exit_code or 1
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        extra = {"summary": post_summary} if post_summary else None
        finalize_run(run_id, status, exit_code, log_path, extra)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    return event_queue


def start_volatility_run(run_id, commands, log_path, plugins, output_path, renderer):
    event_queue, emit = init_run_state(run_id)

    def runner():
        exit_code = 0
        failed_plugins = []
        emit("status", "Running Volatility...")
        try:
            results_dir = os.path.join(output_path, "results")
            os.makedirs(results_dir, exist_ok=True)
            extension = "json" if renderer == "json" else "txt"
            with open(log_path, "w", encoding="utf-8") as log_file:
                for plugin, command in zip(plugins, commands):
                    safe_name = plugin.replace(".", "_")
                    result_path = os.path.join(results_dir, f"{safe_name}.{extension}")
                    emit("milestone", f"Running {plugin}")
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    with open(result_path, "w", encoding="utf-8") as result_file:
                        for line in process.stdout or []:
                            log_file.write(line)
                            log_file.flush()
                            result_file.write(line)
                            result_file.flush()
                    exit_code = process.wait() or 0
                    if exit_code != 0:
                        emit("error", f"{plugin} exited with errors.")
                        failed_plugins.append(plugin)
                        continue
                    emit("milestone", f"Completed {plugin}")
        except FileNotFoundError:
            emit("error", "Volatility is not installed or not on PATH.")
            exit_code = 127
        except OSError:
            emit("error", "Unable to run Volatility.")
            exit_code = 1

        if failed_plugins:
            exit_code = exit_code or 1
            emit("error", f"{len(failed_plugins)} plugin(s) failed.")
        status = "success" if exit_code == 0 else "error"
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        extra = {"failed_plugins": failed_plugins} if failed_plugins else None
        finalize_run(run_id, status, exit_code, log_path, extra)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    return event_queue


def start_artifact_timeline_run(
    run_id,
    log2timeline_cmd,
    psort_cmd,
    log_path,
    output_path,
    timeline_path,
):
    event_queue, emit = init_run_state(run_id)

    def runner():
        exit_code = 0
        emit("status", "Running artifact timeline...")
        try:
            os.makedirs(output_path, exist_ok=True)
            with open(log_path, "w", encoding="utf-8") as log_file:
                emit("milestone", "Running log2timeline")
                process = subprocess.Popen(
                    log2timeline_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in process.stdout or []:
                    log_file.write(line)
                    log_file.flush()
                exit_code = process.wait() or 0
                if exit_code != 0:
                    emit("error", "log2timeline exited with errors.")
                else:
                    emit("milestone", "Running psort")
                    process = subprocess.Popen(
                        psort_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    for line in process.stdout or []:
                        log_file.write(line)
                        log_file.flush()
                    exit_code = process.wait() or 0
                    if exit_code != 0:
                        emit("error", "psort exited with errors.")
        except FileNotFoundError:
            emit("error", "Plaso is not installed or not on PATH.")
            exit_code = 127
        except OSError:
            emit("error", "Unable to run Plaso.")
            exit_code = 1

        status = "success" if exit_code == 0 else "error"
        if status == "success":
            emit("milestone", f"Timeline written to {timeline_path}")
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        extra = {"summary": f"Timeline written to {timeline_path}"} if status == "success" else None
        finalize_run(run_id, status, exit_code, log_path, extra)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    return event_queue


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/file-carving")
def file_carving():
    return render_template("file_carving.html")


@app.route("/artifact-triage")
def artifact_triage():
    return render_template("artifact_triage.html")


@app.route("/artifact-timeline")
def artifact_timeline():
    cases = load_cases()
    return render_template("artifact_timeline.html", cases=cases)


@app.route("/foremost")
def foremost():
    cases = load_cases()
    return render_template("foremost.html", cases=cases)


@app.route("/memory")
def memory():
    return render_template("memory.html")


@app.route("/tools")
def tools():
    return render_template("tools.html")


@app.route("/guides")
def guides():
    return render_template("guides.html")


@app.route("/glossary")
def glossary():
    return render_template("glossary.html")


EZ_CATEGORIES = [
    {
        "id": "program-execution",
        "label": "Program Execution",
        "description": "Evidence of programs that ran on the system",
    },
    {
        "id": "user-activity",
        "label": "User Activity",
        "description": "Evidence of files and folders the user interacted with",
    },
    {
        "id": "system-events",
        "label": "System Events",
        "description": "Windows Event Log entries for security and system activity",
    },
    {
        "id": "file-system",
        "label": "File System",
        "description": "Low-level file system metadata and change journals",
    },
    {
        "id": "persistence",
        "label": "Persistence & Autostart",
        "description": "Mechanisms attackers use to survive reboots",
    },
    {
        "id": "browser-network",
        "label": "Browser & Network",
        "description": "Web browsing history, downloads, and cached data",
    },
]


def get_all_ez_tools_grouped():
    """Get all EZ tools grouped by category for single-page display."""
    categories_with_tools = []
    all_tools_json = []

    for category in EZ_CATEGORIES:
        cat_id = category["id"]
        tools, tools_json = get_tools_for_category(cat_id)
        if tools:
            categories_with_tools.append(
                {
                    "id": cat_id,
                    "label": category["label"],
                    "description": category["description"],
                    "tools": tools,
                }
            )
            all_tools_json.extend(tools_json)

    return categories_with_tools, all_tools_json


@app.route("/eric-zimmerman")
def eric_zimmerman():
    cases = load_cases()
    categories, tools_json = get_all_ez_tools_grouped()
    return render_template(
        "eric_zimmerman.html",
        cases=cases,
        categories=categories,
        tools_json=tools_json,
    )


@app.route("/metadata-extraction")
def metadata_extraction():
    return render_template("metadata_extraction.html")


@app.route("/exiftool")
def exiftool():
    cases = load_cases()
    return render_template("exiftool.html", cases=cases)


@app.route("/strings")
def strings_tool():
    cases = load_cases()
    return render_template("strings.html", cases=cases)


@app.route("/filetype")
def filetype():
    cases = load_cases()
    return render_template("filetype.html", cases=cases)


def get_tools_for_category(category):
    """Get tools filtered by category, with JSON-serializable version."""
    tools = []
    tools_json = []
    for tool_id in EZ_TOOL_ORDER:
        tool = resolve_ez_tool(tool_id)
        if not tool or tool.get("category") != category:
            continue
        tools.append(tool)
        tools_json.append(
            {
                "id": tool["id"],
                "label": tool["label"],
                "summary": tool["summary"],
                "description": tool["description"],
                "input_hint": tool["input_hint"],
                "input_mode": tool["input_mode"],
                "csv_name": tool["csv_name"],
                "curated": tool["curated"],
                "installed": tool["installed"],
                "binary_display": tool["binary_display"],
                "batch_file": tool.get("batch_file"),
                "supports_csvf": tool.get("supports_csvf", True),
            }
        )
    return tools, tools_json


# Legacy category routes - redirect to consolidated page
@app.route("/artifact-parsing/program-execution")
@app.route("/artifact-parsing/user-activity")
@app.route("/artifact-parsing/system-events")
@app.route("/artifact-parsing/file-system")
@app.route("/artifact-parsing/persistence")
@app.route("/artifact-parsing/browser-network")
def artifact_parsing_redirect():
    return redirect(url_for("eric_zimmerman"))


@app.route("/volatility")
def volatility():
    cases = load_cases()
    symbol_path = detect_volatility_symbol_path()
    plugins = load_volatility_plugins()
    return render_template(
        "volatility.html",
        cases=cases,
        symbol_path=symbol_path,
        windows_plugins=plugins.get("windows", []),
        linux_plugins=plugins.get("linux", []),
        mac_plugins=plugins.get("mac", []),
        windows_bundles=WINDOWS_TRIAGE_BUNDLES,
        linux_bundles=LINUX_TRIAGE_BUNDLES,
        windows_defaults=WINDOWS_DEFAULT_PLUGINS,
    )


@app.route("/bulk-extractor")
def bulk_extractor():
    cases = load_cases()
    return render_template("bulk_extractor.html", cases=cases)


@app.route("/scalpel")
def scalpel():
    cases = load_cases()
    return render_template("scalpel.html", cases=cases)


@app.route("/cases", methods=["GET", "POST"])
def cases():
    if request.method == "POST":
        name = request.form.get("name", "").strip() or "Untitled case"
        image_path = request.form.get("image_path", "").strip()
        summary = request.form.get("summary", "").strip()
        file_hash = ""
        hash_error = ""
        if image_path:
            image_path = normalize_path(image_path)
        if image_path and os.path.isfile(image_path):
            try:
                file_hash = compute_sha256(image_path)
            except OSError:
                hash_error = "Unable to read file for hashing."
        elif image_path:
            hash_error = "File not found."
        cases = load_cases()
        slug_source = image_path or name
        case_slug = slugify(os.path.basename(slug_source))
        cases.append(
            {
                "id": uuid.uuid4().hex,
                "name": name,
                "image_path": image_path,
                "summary": summary,
                "slug": case_slug,
                "file_hash": file_hash,
                "hash_error": hash_error,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        save_cases(cases)
        return redirect(url_for("cases"))

    cases = load_cases()
    runs = load_runs()
    runs_by_case = {}
    for run in runs:
        case_id = run.get("case_id")
        if not case_id:
            continue
        output_files, truncated = build_run_manifest(run)
        if output_files:
            run["result_files"] = output_files
            run["result_truncated"] = truncated
        tool = run.get("tool") or "unknown"
        runs_by_case.setdefault(case_id, {}).setdefault(tool, []).append(run)

    grouped_runs = {}
    for case_id, tool_map in runs_by_case.items():
        groups = []
        for tool, tool_runs in tool_map.items():
            tool_runs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
            groups.append({"tool": tool, "runs": tool_runs})
        groups.sort(key=lambda item: item["tool"])
        grouped_runs[case_id] = groups

    return render_template("cases.html", cases=cases, runs_by_case=grouped_runs)


@app.route("/case/<case_id>/results")
def case_results(case_id):
    """Aggregated results view for a case - shows all tool outputs in one place."""
    cases = load_cases()
    case = None
    for c in cases:
        if c.get("id") == case_id:
            case = c
            break

    if not case:
        return render_template(
            "case_results.html",
            case=None,
            error="Case not found.",
            runs=[],
            result_files=[],
            stats={},
        )

    runs = load_runs()
    case_runs = [run for run in runs if run.get("case_id") == case_id]

    # Sort by date (newest first)
    case_runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    # Build result files from all runs
    all_result_files = []
    stats = {
        "total_runs": len(case_runs),
        "successful_runs": 0,
        "failed_runs": 0,
        "tools_used": set(),
        "total_files": 0,
    }

    for run in case_runs:
        tool = run.get("tool", "unknown")
        stats["tools_used"].add(tool)

        if run.get("status") == "success":
            stats["successful_runs"] += 1
        elif run.get("status") == "error":
            stats["failed_runs"] += 1

        # Get result files for this run
        files, truncated = build_run_manifest(run)
        for f in files:
            f["tool"] = tool
            f["run_id"] = run.get("id")
            f["run_status"] = run.get("status", "unknown")
            f["run_date"] = run.get("created_at", "")
            all_result_files.append(f)

        stats["total_files"] += len(files)

    stats["tools_used"] = list(stats["tools_used"])

    return render_template(
        "case_results.html",
        case=case,
        error="",
        runs=case_runs,
        result_files=all_result_files,
        stats=stats,
    )


@app.route("/api/case/<case_id>/search")
def case_search(case_id):
    """Search across all result files in a case."""
    query = request.args.get("q", "").strip().lower()
    file_type = request.args.get("type", "").strip().lower()
    tool_filter = request.args.get("tool", "").strip().lower()
    limit = request.args.get("limit", 100, type=int)
    limit = min(max(1, limit), 500)

    if not query:
        return jsonify({"error": "Search query required."}), 400

    cases = load_cases()
    case = None
    for c in cases:
        if c.get("id") == case_id:
            case = c
            break

    if not case:
        return jsonify({"error": "Case not found."}), 404

    runs = load_runs()
    case_runs = [run for run in runs if run.get("case_id") == case_id]

    results = []
    files_searched = 0

    for run in case_runs:
        tool = run.get("tool", "unknown").lower()

        # Apply tool filter if specified
        if tool_filter and tool_filter not in tool:
            continue

        files, _ = build_run_manifest(run, limit=None)

        for f in files:
            file_path = f.get("path", "")
            file_name = f.get("name", "").lower()

            # Apply file type filter
            if file_type:
                if not file_name.endswith(f".{file_type}"):
                    continue

            # Skip non-text files
            if not file_name.endswith((".txt", ".csv", ".json", ".log")):
                continue

            if not is_path_allowed(file_path, ALLOWED_PATHS):
                continue

            if not os.path.isfile(file_path):
                continue

            files_searched += 1

            # Search file contents
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                    line_num = 0
                    for line in handle:
                        line_num += 1
                        if query in line.lower():
                            results.append({
                                "file": f.get("name"),
                                "path": file_path,
                                "tool": run.get("tool"),
                                "line": line_num,
                                "content": line.strip()[:500],  # Truncate long lines
                            })

                            if len(results) >= limit:
                                break
                    if len(results) >= limit:
                        break
            except OSError:
                continue

        if len(results) >= limit:
            break

    return jsonify({
        "query": query,
        "results": results,
        "total": len(results),
        "truncated": len(results) >= limit,
        "files_searched": files_searched,
    })


@app.route("/api/run", methods=["POST"])
def log_run():
    payload = request.get_json(force=True, silent=True) or {}
    case_id = payload.get("case_id") or None
    output_path = payload.get("output_path", "").strip()
    if case_id and not output_path:
        case_slug = resolve_case_slug(case_id)
        output_path = default_output_path(case_slug, payload.get("tool", "unknown"))
    run = {
        "id": uuid.uuid4().hex,
        "tool": payload.get("tool", "unknown"),
        "case_id": case_id,
        "image_path": payload.get("image_path", ""),
        "output_path": output_path,
        "command": payload.get("command", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    runs = load_runs()
    runs.append(run)
    save_runs(runs)
    return jsonify({"status": "ok", "run_id": run["id"]})


@app.route("/api/foremost/run", methods=["POST"])
def run_foremost():
    payload = request.get_json(force=True, silent=True) or {}
    image_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    types = sanitize_types(payload.get("types") or [])
    quick = bool(payload.get("quick"))
    verbose = bool(payload.get("verbose"))
    safe_mode = bool(payload.get("safe_mode"))

    image_path, image_error = validate_input_path(image_path, "Image", INPUT_ROOTS)
    if image_error:
        return error_response(image_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "foremost")
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path)
    if folder_error:
        return error_response(folder_error)
    if safe_mode and not types:
        return error_response("Select at least one type for safe mode.")

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    config_path = None
    command = []
    if not safe_mode:
        config_path = build_config_for_types(types)
        if types and not config_path:
            return jsonify(
                {"error": "Selected types are not supported by the Foremost config."}
            ), 400
        command = build_foremost_command(
            image_path, output_path, types, quick, verbose, config_path
        )
        command_text = shell_join(command)
    else:
        mode_flags = []
        if quick:
            mode_flags.append("-q")
        if verbose:
            mode_flags.append("-v")
        command_text = (
            f"foremost -i {shlex.quote(image_path)} -o {shlex.quote(output_path)} -t <type> -T"
        )
        if mode_flags:
            command_text = f"{command_text} {' '.join(mode_flags)}"
        command_text = f"{command_text} (safe mode, 10s per type)"

    run, run_error = create_run_record(
        "foremost",
        case_id,
        image_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    if safe_mode:
        start_foremost_safe_run(
            run["id"],
            image_path,
            output_path,
            types,
            quick,
            verbose,
            run["log_path"],
            timeout_seconds=10,
        )
    else:
        start_foremost_run(
            run["id"],
            command,
            run["log_path"],
            output_path,
            config_path=config_path,
        )

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


@app.route("/api/run/<run_id>/events")
def run_events(run_id):
    def get_run_record():
        for run in load_runs():
            if run.get("id") == run_id:
                return run
        return None

    def emit_done(run):
        exit_code = run.get("exit_code")
        if exit_code is None:
            exit_code = 0
        payload = json.dumps({"type": "done", "message": str(exit_code)})
        return f"event: done\ndata: {payload}\n\n"

    def event_stream():
        with RUN_STATE_LOCK:
            state = RUN_STATE.get(run_id)
        if not state:
            run = get_run_record()
            if run and run.get("status") in {"success", "error"}:
                yield emit_done(run)
                return
            yield "event: error\ndata: Run not found\n\n"
            return
        queue_ref = state["queue"]
        while True:
            try:
                event = queue_ref.get(timeout=1)
            except queue.Empty:
                with RUN_STATE_LOCK:
                    state = RUN_STATE.get(run_id)
                if not state:
                    run = get_run_record()
                    if run and run.get("status") in {"success", "error"}:
                        yield emit_done(run)
                    else:
                        yield "event: error\ndata: Run state expired\n\n"
                    break
                if state.get("done"):
                    break
                yield "event: ping\ndata: keepalive\n\n"
                continue

            payload = json.dumps(event)
            yield f"event: {event.get('type','message')}\n"
            yield f"data: {payload}\n\n"

    return app.response_class(event_stream(), mimetype="text/event-stream")


@app.route("/api/run/<run_id>/log")
def run_log(run_id):
    runs = load_runs()
    for run in runs:
        if run.get("id") == run_id:
            log_path = run.get("log_path")
            if log_path and not is_path_allowed(log_path, OUTPUT_ROOTS):
                return jsonify({"error": "Log path is not allowed."}), 403
            if log_path and os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as handle:
                    return jsonify({"log": handle.read()})
            return jsonify({"error": "Log not available."}), 404
    return jsonify({"error": "Run not found."}), 404


@app.route("/api/run/<run_id>/results")
def run_results(run_id):
    runs = load_runs()
    for run in runs:
        if run.get("id") == run_id:
            files, truncated = build_run_manifest(run)
            return jsonify({"files": files, "truncated": truncated})
    return jsonify({"error": "Run not found."}), 404


@app.route("/api/run/<run_id>/status")
def run_status(run_id):
    runs = load_runs()
    for run in runs:
        if run.get("id") == run_id:
            return jsonify(
                {
                    "id": run_id,
                    "tool": run.get("tool"),
                    "status": run.get("status"),
                    "created_at": run.get("created_at"),
                    "output_path": run.get("output_path"),
                }
            )
    return jsonify({"error": "Run not found."}), 404


@app.route("/api/run/<run_id>/tail")
def run_tail(run_id):
    try:
        lines = int(request.args.get("lines", "5"))
    except ValueError:
        lines = 5
    lines = max(1, min(lines, 200))
    runs = load_runs()
    for run in runs:
        if run.get("id") == run_id:
            log_path = run.get("log_path")
            if log_path and not is_path_allowed(log_path, OUTPUT_ROOTS):
                return jsonify({"error": "Log path is not allowed."}), 403
            if not log_path or not os.path.exists(log_path):
                return jsonify({"error": "Log not available."}), 404
            with open(log_path, "r", encoding="utf-8") as handle:
                tail = deque(handle, maxlen=lines)
            return jsonify({"lines": list(tail)})
    return jsonify({"error": "Run not found."}), 404


@app.route("/api/runs")
def list_runs():
    status_filter = request.args.get("status")
    runs = load_runs()
    cases = {case.get("id"): case for case in load_cases()}
    results = []
    for run in runs:
        if status_filter and run.get("status") != status_filter:
            continue
        case = cases.get(run.get("case_id"))
        results.append(
            {
                "id": run.get("id"),
                "tool": run.get("tool"),
                "status": run.get("status"),
                "created_at": run.get("created_at"),
                "command": run.get("command"),
                "image_path": run.get("image_path"),
                "output_path": run.get("output_path"),
                "case_name": case.get("name") if case else None,
            }
        )
    return jsonify({"runs": results})


def build_bulk_command(
    image_path,
    output_path,
    focus_scanners,
    advanced_scanners,
    info_mode,
    histograms,
):
    args = ["bulk_extractor", "-o", output_path]
    if info_mode:
        args.append("-i")
    if not histograms:
        args.extend(["-S", "enable_histograms=NO"])
    if focus_scanners:
        args.extend(["-x", "all"])
        for scanner in focus_scanners:
            args.extend(["-e", scanner])
    for scanner in advanced_scanners:
        args.extend(["-e", scanner])
    args.append(image_path)
    return args


@app.route("/api/bulk-extractor/run", methods=["POST"])
def run_bulk_extractor():
    payload = request.get_json(force=True, silent=True) or {}
    image_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    focus_scanners = sanitize_types(payload.get("focus_scanners") or [])
    advanced_scanners = sanitize_types(payload.get("advanced_scanners") or [])
    info_mode = bool(payload.get("info_mode"))
    histograms = bool(payload.get("histograms", True))

    image_path, image_error = validate_input_path(image_path, "Image", INPUT_ROOTS)
    if image_error:
        return error_response(image_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "bulk-extractor")
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path, must_not_exist=True)
    if folder_error:
        return error_response(folder_error)

    create_error = ensure_output_folder(output_path, create_parent_only=True)
    if create_error:
        return error_response(create_error)

    command = build_bulk_command(
        image_path,
        output_path,
        focus_scanners,
        advanced_scanners,
        info_mode,
        histograms,
    )
    command_text = shell_join(command)

    run, run_error = create_run_record(
        "bulk-extractor",
        case_id,
        image_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_generic_run(run["id"], command, run["log_path"])

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


@app.route("/api/eric-zimmerman/run", methods=["POST"])
def run_eric_zimmerman():
    payload = request.get_json(force=True, silent=True) or {}
    tool_id = (payload.get("tool_id") or payload.get("tool") or "").strip().lower()
    source_path = payload.get("source_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None

    tool = resolve_ez_tool(tool_id)
    if not tool:
        return error_response("Unknown Eric Zimmerman tool.")
    if not tool.get("installed"):
        return error_response(f"{tool['label']} is not installed or not on PATH.")

    source_path, source_error = validate_input_path(source_path, "Source", INPUT_ROOTS)
    if source_error:
        return error_response(source_error)
    if tool["input_mode"] == "file" and not os.path.isfile(source_path):
        return error_response("Source path must be a file for this tool.")
    if tool["input_mode"] == "dir" and not os.path.isdir(source_path):
        return error_response("Source path must be a directory for this tool.")

    output_path, output_error = resolve_output_path(
        output_path,
        case_id,
        f"eric-zimmerman/{tool_id}",
    )
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path)
    if folder_error:
        return error_response(folder_error)

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    command = build_ez_command(tool, source_path, output_path)
    command_text = shell_join(command)

    output_file = None
    extra = None
    if tool.get("supports_csvf", True):
        output_file = os.path.join(output_path, tool["csv_name"])
        extra = {"output_file": output_file}
    run, run_error = create_run_record(
        f"EZ {tool['label']}",
        case_id,
        source_path,
        output_path,
        command_text,
        extra=extra,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_generic_run(run["id"], command, run["log_path"])

    response = {
        "status": "running",
        "command": command_text,
        "output_path": output_path,
        "run_id": run["id"],
    }
    if output_file:
        response["output_file"] = output_file
    return jsonify(response)


@app.route("/api/scalpel/run", methods=["POST"])
def run_scalpel():
    payload = request.get_json(force=True, silent=True) or {}
    image_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    types = sanitize_types(payload.get("types") or [])
    organize = bool(payload.get("organize", True))

    image_path, image_error = validate_input_path(image_path, "Image", INPUT_ROOTS)
    if image_error:
        return error_response(image_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "scalpel")
    if output_error:
        return error_response(output_error)
    if not types:
        return error_response("Select at least one file type.")

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    config_path, missing = build_scalpel_config_for_types(types)
    if missing:
        return jsonify(
            {
                "error": "Unsupported Scalpel types: "
                + ", ".join(sorted(set(missing)))
                + ".",
            }
        ), 400
    if not config_path:
        return jsonify({"error": "Unable to build Scalpel config."}), 400

    command = ["scalpel", "-c", config_path, "-o", output_path]
    if not organize:
        command.append("-O")
    command.append(image_path)
    command_text = shell_join(command)

    run, run_error = create_run_record(
        "scalpel",
        case_id,
        image_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    def finalize():
        summary = ""
        audit_path = os.path.join(output_path, "audit.txt")
        counts = parse_audit_counts(audit_path)
        summary = summarize_counts(counts)
        if summary:
            summary = f"Final counts: {summary}"
        try:
            os.remove(config_path)
        except OSError:
            pass
        return summary

    start_generic_run(run["id"], command, run["log_path"], post_process=finalize)

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


@app.route("/api/volatility/run", methods=["POST"])
def run_volatility():
    payload = request.get_json(force=True, silent=True) or {}
    image_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    symbol_path = payload.get("symbol_path", "").strip()
    plugins = payload.get("plugins") or []
    renderer = (payload.get("renderer") or "json").strip().lower()

    image_path, image_error = validate_input_path(image_path, "Image", INPUT_ROOTS)
    if image_error:
        return error_response(image_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "volatility")
    if output_error:
        return error_response(output_error)

    if not plugins:
        return error_response("Select at least one plugin.")

    if not symbol_path:
        symbol_path = detect_volatility_symbol_path()
    if not symbol_path:
        return error_response("Symbol path is required.")
    symbol_path = normalize_path(symbol_path)
    if SYMBOL_ROOTS and not is_path_allowed(symbol_path, SYMBOL_ROOTS):
        return error_response("Symbol path is outside the allowed roots.")
    if not os.path.isdir(symbol_path):
        return error_response("Symbol path not found.")

    if renderer not in {"json", "pretty"}:
        renderer = "json"

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    commands = build_volatility_commands(
        image_path,
        output_path,
        symbol_path,
        plugins,
        renderer,
    )
    command_text = " && ".join(shell_join(cmd) for cmd in commands)

    run, run_error = create_run_record(
        "volatility",
        case_id,
        image_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_volatility_run(
        run["id"],
        commands,
        run["log_path"],
        plugins,
        output_path,
        renderer,
    )

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


@app.route("/api/artifact-triage/run", methods=["POST"])
def run_artifact_timeline():
    payload = request.get_json(force=True, silent=True) or {}
    image_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    user_timezone = (payload.get("timezone") or "UTC").strip() or "UTC"

    image_path, image_error = validate_input_path(image_path, "Evidence", INPUT_ROOTS)
    if image_error:
        return error_response(image_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "artifact-triage")
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path)
    if folder_error:
        return error_response(folder_error)

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    log2timeline_cmd, psort_cmd, storage_path, timeline_path = build_plaso_commands(
        image_path,
        output_path,
        user_timezone,
    )
    command_text = " && ".join(
        [shell_join(log2timeline_cmd), shell_join(psort_cmd)]
    )

    run, run_error = create_run_record(
        "artifact-triage",
        case_id,
        image_path,
        output_path,
        command_text,
        extra={
            "timeline_path": timeline_path,
            "storage_path": storage_path,
        },
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_artifact_timeline_run(
        run["id"],
        log2timeline_cmd,
        psort_cmd,
        run["log_path"],
        output_path,
        timeline_path,
    )

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
            "timeline_path": timeline_path,
        }
    )


@app.route("/api/browse")
def browse():
    target = request.args.get("path", "/cases")
    target = normalize_path(target)
    if not is_path_allowed(target, ALLOWED_PATHS):
        return jsonify({"error": "Access denied", "path": target}), 403

    if not os.path.isdir(target):
        return jsonify({"error": "Not a directory", "path": target}), 400

    entries = []
    try:
        with os.scandir(target) as it:
            for entry in it:
                if entry.name.startswith("."):
                    continue
                entries.append(
                    {
                        "name": entry.name,
                        "path": entry.path,
                        "type": "dir" if entry.is_dir() else "file",
                    }
                )
    except OSError:
        return jsonify({"error": "Unable to read directory", "path": target}), 400

    entries.sort(key=lambda item: (item["type"] != "dir", item["name"].lower()))
    parent = os.path.dirname(target) if target != os.path.dirname(target) else None
    if parent and not is_path_allowed(parent, ALLOWED_PATHS):
        parent = None

    return jsonify({"path": target, "parent": parent, "entries": entries})


@app.route("/view-file")
def view_file():
    target = request.args.get("path", "")
    view_param = request.args.get("view", "").strip().lower()

    # Determine if file supports table view
    lower_target = target.lower() if target else ""
    is_json = lower_target.endswith(".json")
    is_csv = lower_target.endswith(".csv")
    is_txt = lower_target.endswith(".txt")

    # Detect text file format for table parsing
    text_format = None
    if is_txt and target:
        try:
            text_format = detect_text_table_format(target)
        except Exception:
            text_format = None

    table_available = is_json or is_csv or bool(text_format)

    # Default to table view for structured data, raw for others
    if view_param:
        view_mode = view_param
    else:
        view_mode = "table" if table_available else "raw"

    if not target:
        return render_template(
            "file_viewer.html",
            path="",
            content="",
            truncated=False,
            error="Missing file path.",
            view_mode=view_mode,
            table_available=False,
            table_error="",
            table_data=None,
            table_total=0,
            table_truncated=False,
        )

    target = normalize_path(target)
    lower_target = target.lower()
    is_json = lower_target.endswith(".json")
    is_csv = lower_target.endswith(".csv")
    is_txt = lower_target.endswith(".txt")

    # Re-detect text format after normalization
    text_format = None
    if is_txt:
        try:
            text_format = detect_text_table_format(target)
        except Exception:
            text_format = None

    table_available = is_json or is_csv or bool(text_format)

    # Re-evaluate default view mode after path normalization
    if not view_param:
        view_mode = "table" if table_available else "raw"

    if not is_path_allowed(target, ALLOWED_PATHS):
        return render_template(
            "file_viewer.html",
            path=target,
            content="",
            truncated=False,
            error="Access denied.",
            view_mode=view_mode,
            table_available=table_available,
            table_error="",
            table_data=None,
            table_total=0,
            table_truncated=False,
        )
    if not os.path.isfile(target):
        return render_template(
            "file_viewer.html",
            path=target,
            content="",
            truncated=False,
            error="File not found.",
            view_mode=view_mode,
            table_available=table_available,
            table_error="",
            table_data=None,
            table_total=0,
            table_truncated=False,
        )

    table_data = None
    table_error = ""
    table_total = 0
    table_truncated = False

    if view_mode == "table":
        if not table_available:
            table_error = "Table view is only available for JSON, CSV, and supported text files."
        else:
            try:
                # Load initial 100 rows for virtual scroll (50 per batch after)
                if is_csv:
                    table_data, table_total, table_truncated = parse_csv_table(target, row_limit=100)
                elif is_json:
                    table_data, table_total, table_truncated = parse_json_table(target, row_limit=100)
                elif text_format == "strings":
                    table_data, table_total, table_truncated = parse_strings_table(target, row_limit=100)
                elif text_format == "foremost_audit":
                    table_data, table_total, table_truncated = parse_foremost_audit(target, row_limit=100)
                elif text_format == "bulk_extractor":
                    table_data, table_total, table_truncated = parse_bulk_extractor_feature(target, row_limit=100)
                else:
                    table_error = "Unable to parse file as table."
            except (ValueError, json.JSONDecodeError) as exc:
                table_error = str(exc)
            except OSError:
                table_error = "Unable to read file."

    content = ""
    truncated = False
    if view_mode != "table" or table_error:
        try:
            content, truncated = read_text_preview(target)
        except OSError:
            return render_template(
                "file_viewer.html",
                path=target,
                content="",
                truncated=False,
                error="Unable to read file.",
                view_mode=view_mode,
                table_available=table_available,
                table_error=table_error,
                table_data=table_data,
                table_total=table_total,
                table_truncated=table_truncated,
            )

    return render_template(
        "file_viewer.html",
        path=target,
        content=content,
        truncated=truncated,
        error="",
        view_mode=view_mode,
        table_available=table_available,
        table_error=table_error,
        table_data=table_data,
        table_total=table_total,
        table_truncated=table_truncated,
    )


@app.route("/api/table-rows")
def api_table_rows():
    """API endpoint for virtual scroll - returns batches of table rows."""
    target = request.args.get("path", "")
    offset = request.args.get("offset", 0, type=int)
    limit = request.args.get("limit", 50, type=int)

    # Clamp values
    offset = max(0, offset)
    limit = min(max(1, limit), 200)  # Max 200 rows per request

    if not target:
        return jsonify({"error": "Missing file path."}), 400

    target = normalize_path(target)
    lower_target = target.lower()
    is_json = lower_target.endswith(".json")
    is_csv = lower_target.endswith(".csv")
    is_txt = lower_target.endswith(".txt")

    # Detect text file format
    text_format = None
    if is_txt:
        try:
            text_format = detect_text_table_format(target)
        except Exception:
            text_format = None

    if not (is_json or is_csv or text_format):
        return jsonify({"error": "Only JSON, CSV, and supported text files allowed."}), 400

    if not is_path_allowed(target, ALLOWED_PATHS):
        return jsonify({"error": "Access denied."}), 403

    if not os.path.isfile(target):
        return jsonify({"error": "File not found."}), 404

    try:
        # Parse window for the requested offset/limit while counting full rows.
        if is_csv:
            table_data, total_rows, _ = parse_csv_table(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif is_json:
            table_data, total_rows, _ = parse_json_table(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif text_format == "strings":
            table_data, total_rows, _ = parse_strings_table(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif text_format == "foremost_audit":
            table_data, total_rows, _ = parse_foremost_audit(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        elif text_format == "bulk_extractor":
            table_data, total_rows, _ = parse_bulk_extractor_feature(
                target,
                row_limit=limit,
                row_offset=offset,
            )
        else:
            return jsonify({"error": "Unable to parse file format."}), 400

        sliced_rows = table_data.get("rows", [])

        return jsonify({
            "columns": table_data.get("columns", []),
            "rows": sliced_rows,
            "offset": offset,
            "limit": limit,
            "total": total_rows,
            "has_more": offset + len(sliced_rows) < total_rows,
        })
    except (ValueError, json.JSONDecodeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except OSError:
        return jsonify({"error": "Unable to read file."}), 500


# --- Metadata Extraction Tools ---


def build_exiftool_command(source_path, output_path, output_format, options):
    """Build exiftool command with given options."""
    output_file = os.path.join(
        output_path,
        f"metadata.{output_format}" if output_format != "json" else "metadata.json",
    )
    args = ["exiftool"]

    # Output format
    if output_format == "json":
        args.append("-json")
    else:
        args.append("-csv")

    # Options
    if options.get("recursive"):
        args.append("-r")
    if options.get("extract_unknown"):
        args.append("-u")
    if options.get("duplicates"):
        args.append("-a")

    # Always include common forensic tags
    args.extend(["-G1", "-s"])

    args.append(source_path)
    return args, output_file


def start_exiftool_run(run_id, command, log_path, output_path, output_file):
    """Run exiftool in a background thread."""
    event_queue, emit = init_run_state(run_id)

    def runner():
        emit("status", "Running ExifTool...")
        file_count = 0
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                with open(output_file, "w", encoding="utf-8") as out_file:
                    process = subprocess.Popen(
                        command,
                        stdout=out_file,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    # Read stderr for progress
                    while True:
                        line = process.stderr.readline() if process.stderr else ""
                        if not line:
                            if process.poll() is not None:
                                break
                            continue
                        log_file.write(line)
                        log_file.flush()

                    exit_code = process.poll() or 0

            # Count files processed by checking output
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    if output_file.endswith(".json"):
                        try:
                            data = json.loads(content)
                            file_count = len(data) if isinstance(data, list) else 1
                        except json.JSONDecodeError:
                            file_count = 0
                    else:
                        # CSV: count lines minus header
                        file_count = max(0, content.count("\n") - 1)

            emit("milestone", f"Processed {file_count} files")

        except FileNotFoundError:
            emit("error", "ExifTool is not installed or not on PATH.")
            exit_code = 127
        except OSError as e:
            emit("error", f"Unable to run ExifTool: {e}")
            exit_code = 1

        status = "success" if exit_code == 0 else "error"
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        finalize_run(
            run_id, status, exit_code, log_path, {"file_count": file_count}
        )

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return event_queue


@app.route("/api/exiftool/run", methods=["POST"])
def run_exiftool():
    payload = request.get_json(force=True, silent=True) or {}
    source_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    output_format = payload.get("output_format", "csv").strip().lower()
    if output_format not in {"csv", "json"}:
        output_format = "csv"
    options = {
        "recursive": bool(payload.get("recursive", True)),
        "extract_unknown": bool(payload.get("extract_unknown", False)),
        "duplicates": bool(payload.get("duplicates", False)),
    }

    source_path, source_error = validate_input_path(source_path, "Source", INPUT_ROOTS)
    if source_error:
        return error_response(source_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "exiftool")
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path)
    if folder_error:
        return error_response(folder_error)

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    command, output_file = build_exiftool_command(
        source_path, output_path, output_format, options
    )
    command_text = shell_join(command) + f" > {shlex.quote(output_file)}"

    run, run_error = create_run_record(
        "exiftool",
        case_id,
        source_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_exiftool_run(
        run["id"],
        command,
        run["log_path"],
        output_path,
        output_file,
    )

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


def build_strings_command(source_path, output_path, encoding, min_length, show_offsets):
    """Build strings command with given options."""
    output_file = os.path.join(output_path, "strings.txt")
    args = ["strings"]

    # Encoding
    if encoding == "l":
        args.extend(["-e", "l"])  # UTF-16 LE
    elif encoding == "S":
        args.extend(["-e", "S"])  # All encodings

    # Minimum length
    args.extend(["-n", str(min_length)])

    # Show offsets
    if show_offsets:
        args.append("-t")
        args.append("x")  # hex offsets

    args.append(source_path)
    return args, output_file


def start_strings_run(run_id, command, log_path, output_path, output_file):
    """Run strings in a background thread."""
    event_queue, emit = init_run_state(run_id)

    def runner():
        emit("status", "Running strings...")
        string_count = 0
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                with open(output_file, "w", encoding="utf-8") as out_file:
                    process = subprocess.Popen(
                        command,
                        stdout=out_file,
                        stderr=log_file,
                        text=True,
                    )
                    process.wait()
                    exit_code = process.returncode

            # Count strings found
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    string_count = sum(1 for _ in f)

            emit("milestone", f"Found {string_count} strings")

        except FileNotFoundError:
            emit("error", "strings is not installed or not on PATH.")
            exit_code = 127
        except OSError as e:
            emit("error", f"Unable to run strings: {e}")
            exit_code = 1

        status = "success" if exit_code == 0 else "error"
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        finalize_run(
            run_id, status, exit_code, log_path, {"string_count": string_count}
        )

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return event_queue


@app.route("/api/strings/run", methods=["POST"])
def run_strings():
    payload = request.get_json(force=True, silent=True) or {}
    source_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    encoding = payload.get("encoding", "s").strip()
    try:
        min_length = int(payload.get("min_length", 4))
    except (ValueError, TypeError):
        min_length = 4
    min_length = max(1, min(min_length, 100))
    show_offsets = bool(payload.get("show_offsets", True))

    source_path, source_error = validate_input_path(source_path, "Source", INPUT_ROOTS)
    if source_error:
        return error_response(source_error)

    if not os.path.isfile(source_path):
        return error_response("Source must be a file.")

    output_path, output_error = resolve_output_path(output_path, case_id, "strings")
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path)
    if folder_error:
        return error_response(folder_error)

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    command, output_file = build_strings_command(
        source_path, output_path, encoding, min_length, show_offsets
    )
    command_text = shell_join(command) + f" > {shlex.quote(output_file)}"

    run, run_error = create_run_record(
        "strings",
        case_id,
        source_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_strings_run(
        run["id"],
        command,
        run["log_path"],
        output_path,
        output_file,
    )

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


def build_filetype_command_preview(source_path, mode, recursive):
    file_cmd = ["file"]
    if mode == "mime":
        file_cmd.extend(["--mime-type", "-b"])
    elif mode == "brief":
        file_cmd.append("-b")
    file_cmd_text = " ".join(file_cmd)
    quoted_source = shlex.quote(source_path)

    if os.path.isfile(source_path):
        return f"{file_cmd_text} {quoted_source}"
    if os.path.isdir(source_path):
        if recursive:
            return f"find {quoted_source} -type f -exec {file_cmd_text} {{}} \\;"
        return f"find {quoted_source} -maxdepth 1 -type f -exec {file_cmd_text} {{}} \\;"
    return f"{file_cmd_text} {quoted_source}"


def start_filetype_run(run_id, source_path, log_path, output_path, mode, recursive, mismatch_only):
    """Run file type detection in a background thread."""
    event_queue, emit = init_run_state(run_id)
    output_file = os.path.join(output_path, "filetypes.csv")

    def runner():
        emit("status", "Detecting file types...")
        file_count = 0
        mismatch_count = 0
        results = []

        try:
            # Get list of files to process
            if os.path.isfile(source_path):
                files_to_check = [source_path]
            elif recursive:
                files_to_check = []
                for root, _, files in os.walk(source_path):
                    for f in files:
                        files_to_check.append(os.path.join(root, f))
            else:
                files_to_check = [
                    os.path.join(source_path, f)
                    for f in os.listdir(source_path)
                    if os.path.isfile(os.path.join(source_path, f))
                ]

            with open(log_path, "w", encoding="utf-8") as log_file:
                for filepath in files_to_check:
                    try:
                        # Run file command
                        if mode == "mime":
                            cmd = ["file", "--mime-type", "-b", filepath]
                        elif mode == "brief":
                            cmd = ["file", "-b", filepath]
                        else:
                            cmd = ["file", filepath]

                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        detected_type = result.stdout.strip()

                        # Get extension
                        _, ext = os.path.splitext(filepath)
                        ext = ext.lower().lstrip(".")

                        # Check for mismatch
                        is_mismatch = False
                        if ext and mode == "mime":
                            # Basic mismatch detection
                            ext_type_map = {
                                "jpg": "image/jpeg",
                                "jpeg": "image/jpeg",
                                "png": "image/png",
                                "gif": "image/gif",
                                "pdf": "application/pdf",
                                "doc": "application/msword",
                                "docx": "application/vnd.openxmlformats",
                                "xls": "application/vnd.ms-excel",
                                "xlsx": "application/vnd.openxmlformats",
                                "zip": "application/zip",
                                "exe": "application/x-dosexec",
                                "dll": "application/x-dosexec",
                                "txt": "text/plain",
                                "html": "text/html",
                                "js": "text/javascript",
                                "json": "application/json",
                                "xml": "text/xml",
                            }
                            expected = ext_type_map.get(ext, "")
                            if expected and not detected_type.startswith(expected.split("/")[0]):
                                is_mismatch = True
                                mismatch_count += 1

                        if not mismatch_only or is_mismatch:
                            results.append({
                                "path": filepath,
                                "extension": ext,
                                "detected_type": detected_type,
                                "mismatch": is_mismatch,
                            })

                        file_count += 1
                        if file_count % 100 == 0:
                            emit("milestone", f"Processed {file_count} files...")

                    except subprocess.TimeoutExpired:
                        log_file.write(f"Timeout: {filepath}\n")
                    except OSError as e:
                        log_file.write(f"Error: {filepath}: {e}\n")

            # Write results to CSV
            with open(output_file, "w", encoding="utf-8") as csv_file:
                csv_file.write("Path,Extension,Detected Type,Mismatch\n")
                for r in results:
                    mismatch_str = "Yes" if r["mismatch"] else "No"
                    # Escape commas in detected_type
                    detected = r["detected_type"].replace('"', '""')
                    csv_file.write(
                        f'"{r["path"]}","{r["extension"]}","{detected}","{mismatch_str}"\n'
                    )

            emit("milestone", f"Processed {file_count} files, {mismatch_count} mismatches")
            exit_code = 0

        except FileNotFoundError:
            emit("error", "file command is not installed or not on PATH.")
            exit_code = 127
        except OSError as e:
            emit("error", f"Unable to run file type detection: {e}")
            exit_code = 1

        status = "success" if exit_code == 0 else "error"
        emit("status", run_completion_message(status))
        emit("done", str(exit_code))

        mark_run_done(run_id)
        finalize_run(
            run_id,
            status,
            exit_code,
            log_path,
            {"file_count": file_count, "mismatch_count": mismatch_count},
        )

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return event_queue


@app.route("/api/filetype/run", methods=["POST"])
def run_filetype():
    payload = request.get_json(force=True, silent=True) or {}
    source_path = payload.get("image_path", "").strip()
    output_path = payload.get("output_path", "").strip()
    case_id = payload.get("case_id") or None
    mode = payload.get("mode", "mime").strip()
    recursive = bool(payload.get("recursive", True))
    mismatch_only = bool(payload.get("mismatch_only", False))

    source_path, source_error = validate_input_path(source_path, "Source", INPUT_ROOTS)
    if source_error:
        return error_response(source_error)

    output_path, output_error = resolve_output_path(output_path, case_id, "filetype")
    if output_error:
        return error_response(output_error)

    folder_error = validate_output_folder(output_path)
    if folder_error:
        return error_response(folder_error)

    create_error = ensure_output_folder(output_path)
    if create_error:
        return error_response(create_error)

    command_text = build_filetype_command_preview(source_path, mode, recursive)

    run, run_error = create_run_record(
        "filetype",
        case_id,
        source_path,
        output_path,
        command_text,
    )
    if run_error:
        return jsonify({"error": run_error}), 400

    start_filetype_run(
        run["id"],
        source_path,
        run["log_path"],
        output_path,
        mode,
        recursive,
        mismatch_only,
    )

    return jsonify(
        {
            "status": "running",
            "command": command_text,
            "output_path": output_path,
            "run_id": run["id"],
        }
    )


if __name__ == "__main__":
    app.run(debug=False)
