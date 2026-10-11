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


