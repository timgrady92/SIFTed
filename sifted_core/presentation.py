"""Evidence types and curated workflow bundles for the interface."""

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


