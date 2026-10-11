"""Evidence types and curated workflow bundles for the interface."""
import os

ARTIFACT_TYPES = {
    "disk_image": {
        "label": "Disk Image",
        "extensions": [".dd", ".raw", ".e01", ".ex01", ".aff", ".img", ".dmg"],
        "icon": "disk",
    },
    "memory_dump": {
        "label": "Memory Dump",
        "extensions": [".raw", ".mem", ".vmem", ".dmp", ".lime", ".core"],
        "icon": "memory",
    },
    "registry": {
        "label": "Registry Hive",
        "extensions": [],
        "names": ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER.DAT", "UsrClass.dat"],
        "icon": "registry",
    },
    "event_log": {
        "label": "Event Log",
        "extensions": [".evtx", ".evt"],
        "icon": "log",
    },
    "artifact_file": {
        "label": "Artifact File",
        "extensions": [".pf", ".lnk", ".db", ".sqlite", ".dat"],
        "icon": "file",
    },
    "other": {
        "label": "Other",
        "extensions": [],
        "icon": "generic",
    },
}


def detect_artifact_type(path):
    """Auto-detect artifact type from file extension or name."""
    if not path:
        return "other"
    basename = os.path.basename(path)
    basename_upper = basename.upper()
    ext = os.path.splitext(path)[1].lower()

    # Check registry hives by name first (they often have no extension)
    registry_info = ARTIFACT_TYPES.get("registry", {})
    for name in registry_info.get("names", []):
        if basename_upper == name.upper() or basename_upper.endswith(name.upper()):
            return "registry"

    # Check extensions for each type
    for type_key, type_info in ARTIFACT_TYPES.items():
        if type_key == "registry":
            continue
        if ext in type_info.get("extensions", []):
            return type_key

    return "other"


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


