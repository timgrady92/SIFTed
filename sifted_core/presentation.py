"""Evidence types and shared, read-only interface projections."""

from .evidence_profile import interpretation

ARTIFACT_TYPES = {
    "disk_image": {
        "label": "Disk Image",
        "icon": "disk",
    },
    "memory_dump": {
        "label": "Memory Dump",
        "icon": "memory",
    },
    "registry": {
        "label": "Registry Hive",
        "icon": "registry",
    },
    "event_log": {
        "label": "Event Log",
        "icon": "log",
    },
    "artifact_file": {
        "label": "Artifact File",
        "icon": "file",
    },
    "other": {
        "label": "Other",
        "icon": "generic",
    },
}


def evidence_presentation(item, observed=None):
    """Describe recorded evidence without reading files or launching a profiler.

    Cards use the same content interpretation as analysis. Verification badges
    describe the recorded intake; opening evidence still checks availability.
    Captured outputs stay distinct from registered and verified acquisitions.
    """
    derived = item.get("origin") == "derived"
    status = item.get("status", "needs_intake")
    content = observed or (interpretation(item, item["profile"]) if item.get("profile") else {})
    kind = content.get("kind", "unknown")
    icon = {"disk": "disk", "ewf": "disk", "filesystem": "disk", "memory": "memory",
            "registry": "registry", "evtx": "log", "sqlite": "database", "directory": "folder"}.get(kind, "file")
    label = content.get("label") or "Awaiting profile"
    if derived and not observed:
        label = {"filesystem_block_sample": "Block sample", "carved_file": "Carved file"}.get(item.get("artifact_kind"), "Captured file")
    tone, state = {"ready": ("success", "Verified"), "pending": ("pending", "Verifying"),
                   "failed": ("error", "Verification failed"), "retired": ("muted", "Retired")}.get(status, ("pending", "Intake required"))
    if derived:
        tone, state = "muted", "Captured"
    elif status == "ready" and observed and not observed.get("available"):
        tone, state = "error", "Reverify"
    return {"label": label, "icon": icon, "kind": kind, "state": state, "tone": tone,
            "action": "Examine file" if derived else "Analyze" if status == "ready" else "Review intake"}


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


