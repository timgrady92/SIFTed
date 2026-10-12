"""Content observations shared by intake, execution and derived evidence views.

Signatures describe format candidates, never prove a complete/valid acquisition.
Filenames do not establish format. Native adapters validate before analysis.
"""
import os
import json
import sys
import stat
import subprocess
from pathlib import Path

from .integrity import evidence_path, hash_file, IntegrityFailure
from .storage import utc_now
from .tool_base import ValidationError, executable, signature
from .zimmerman import validate_file

PROFILE_VERSION = 2
ACQUISITION_CONTEXT_KINDS = {"unknown", "content", "text"}
LABELS = {
    "unknown": "Unidentified content", "directory": "Collected directory",
    "disk": "Disk image", "filesystem": "Filesystem image", "ewf": "EWF disk container",
    "memory": "Memory image", "registry": "Registry hive", "evtx": "Windows Event Log",
    "mft": "NTFS master file table", "shortcut": "Windows shortcut", "jump_list": "Jump List",
    "recycle_bin": "Recycle Bin metadata", "recent_cache": "RecentFileCache",
    "sqlite": "SQLite database", "pdf": "PDF document", "text": "Text content",
    "content": "Identified content", "compound": "Compound document", "block": "Filesystem block sample",
}


def profile(path, settings, *, probe=None, image_paths=None):
    path = Path(evidence_path(path))
    before = signature(path)
    result = {"version": PROFILE_VERSION, "profiled_at": utc_now(), "signature": before,
              "kind": "unknown", "label": LABELS["unknown"], "basis": "No recognized content signature",
              "mime": None, "available": True, "note": "", "observations": []}
    if path.is_dir():
        return {**result, "kind": "directory", "label": LABELS["directory"], "basis": "Directory manifest"}
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Evidence must be a regular file.")
        header = handle.read(8192)
        handle.seek(max(0, before[2] - 512))
        footer = handle.read(512)
    kind = "unknown"
    if header.startswith((b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00")) and len(header) >= 13:
        kind = "ewf"
    elif header.startswith(b"regf") and len(header) >= 512:
        kind = "registry"
        result["registry_identity"] = header[48:112].decode("utf-16-le", errors="replace").strip("\0")
    elif header.startswith(b"SQLite format 3\0") and len(header) >= 100:
        kind = "sqlite"
    elif b"%PDF-" in header[:1024]:
        kind = "pdf"
    elif header.startswith((b"PAGEDUMP", b"PAGEDU64")) and len(header) >= 4096:
        kind = "memory"
    elif header[:8] == b"EMiL\x01\x00\x00\x00" and len(header) >= 32:
        kind = "memory"
    elif (header[:4] in {b"\x01\x00\x00\x00", b"\x02\x00\x00\x00"}
          and bytes.fromhex("4c0000000114020000000000c000000000000046") in header[12:80]
          and footer.endswith(b"\xab\xfb\xbf\xba")):
        kind = "jump_list"
    elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        # CFB also contains Office documents and many other formats. Never
        # recommend Jump List parsing on this shared signature alone.
        kind = "compound"
        try:
            checked = subprocess.run([sys.executable, str(Path(__file__).with_name("compound_profile.py")), str(path)],
                                     capture_output=True, timeout=5, check=True)
            structure = json.loads(checked.stdout)
            if structure.get("jump_list"):
                kind = "jump_list"
                result["compound_parser"] = {"name": structure["parser"], "version": structure["version"]}
            if structure.get("error"):
                result["observations"].append(structure["error"])
        except (OSError, ValueError, subprocess.SubprocessError):
            result["observations"].append("Compound structure inspection was unavailable or exceeded its resource limit.")
    else:
        candidates = [("evtx", "evtxecmd", header.startswith(b"ElfFile\0")),
                      ("mft", "mftecmd", header.startswith(b"FILE") and len(header) >= 48),
                      ("shortcut", "lecmd", header.startswith(bytes.fromhex("4c0000000114020000000000c000000000000046"))),
                      ("recent_cache", "recentfilecacheparser", header.startswith(b"\xfe\xff\xee\xff"))]
        for candidate, parser, matches in candidates:
            if matches:
                try:
                    validate_file(parser, path)
                    kind = candidate
                    break
                except ValidationError as exc:
                    result["observations"].append(str(exc))
        # $I v1/v2: validate the complete UTF-16 path and Windows FILETIME,
        # not the ambiguous integer version field or filename.
        version = int.from_bytes(header[:8], "little")
        if kind == "unknown" and version in {1, 2} and len(header) >= 28:
            count = 260 if version == 1 else int.from_bytes(header[24:28], "little")
            start = 24 if version == 1 else 28
            timestamp = int.from_bytes(header[16:24], "little")
            if 1 <= count <= 4096 and before[2] == start + count * 2 and 0 < timestamp < 2650467744000000000:
                try:
                    name = header[start:start + count * 2].decode("utf-16-le").rstrip("\0")
                    if len(name) >= 3 and (name[1:3] == ':\\' or name.startswith('\\\\')):
                        kind = "recycle_bin"
                except UnicodeError:
                    pass
        mbr = len(header) >= 512 and header[510:512] == b"\x55\xaa" and any(
            header[pos] in {0, 128} and header[pos + 4] and int.from_bytes(header[pos + 12:pos + 16], "little")
            for pos in range(446, 510, 16))
        if kind == "unknown":
            if header[512:520] == b"EFI PART" or header[4096:4104] == b"EFI PART" or mbr:
                kind = "disk"
            elif (header[1080:1082] == b"\x53\xef" or header.startswith(b"XFSB") or header[3:11] == b"NTFS    "
                  or header[54:62] in {b"FAT12   ", b"FAT16   "} or header[82:90] == b"FAT32   "):
                kind = "filesystem"
            elif footer.startswith(b"koly") and len(footer) == 512 or header.startswith(b"AFF10\r\n\0"):
                kind = "disk"
    if kind != "unknown":
        result["basis"] = "Content signature and bounded structure checks"
        result["observations"].append("Format candidate; native analysis validates the complete structure.")
    try:
        command = executable("filetype", ["file"], settings)
        detected = subprocess.run([*command, "-b", "--mime-type", "--", str(path)],
                                  capture_output=True, timeout=5, check=True)
        mime = detected.stdout[:512].decode("utf-8", errors="replace").strip()
        if '/' in mime and '\n' not in mime:
            result["mime"] = mime
        result["detector"] = {"argv": [*command, "-b", "--mime-type", "--", str(path)], "method": "file/libmagic",
                              "executable_sha256": {arg: hash_file(Path(arg).resolve())[0] for arg in command if Path(arg).is_absolute() and Path(arg).is_file()}}
        if kind == "unknown" and result["mime"] not in {None, "application/octet-stream", "application/x-empty", "inode/x-empty"}:
            kind = "text" if mime.startswith("text/") or mime in {"application/json", "application/xml"} else "content"
            result["basis"] = "Native file / libmagic content identification"
    except (ValidationError, OSError, subprocess.SubprocessError) as exc:
        result["observations"].append("Native file identification unavailable: " + str(exc))
    result.update(kind=kind, label=result["mime"] if kind == "content" else LABELS[kind])
    if probe:
        from .evidence_assessment import assess
        assess(path, result, settings, probe, image_paths)
        kind = result['kind']
        result['label'] = result['mime'] if kind == 'content' else LABELS[kind]
    if signature(path) != before:
        raise IntegrityFailure("Evidence changed while profiling.")
    if kind == "unknown" and not result['note']:
        result["note"] = "No confident format identification. Raw disk and memory captures may need acquisition context."
    return result


def evidence_type(observed):
    kind = observed["kind"]
    if kind in {"disk", "filesystem", "ewf"}:
        return "disk_image"
    return {"memory": "memory_dump", "registry": "registry", "evtx": "event_log", "unknown": "other",
            "directory": "other"}.get(kind, "artifact_file")


def acquisition_context(item):
    """Generic byte observations cannot establish what the analyst acquired.

    This is a recorded-intake projection, shared by cards and the workspace.
    No filename guesses, file reads, or reclassification happen during display.
    """
    editable = bool(item and item.get("origin", "registered") == "registered"
                    and item.get("status") == "ready"
                    and item.get("profile", {}).get("kind") in ACQUISITION_CONTEXT_KINDS)
    return {"editable": editable, "needed": editable and item.get("type_basis") != "analyst"
            and item['profile']['kind'] == 'unknown'}


def interpretation(item, observed):
    """Analyst context affects recommendations without rewriting the observation."""
    value = dict(observed)
    chosen = item.get("type")
    expected = {"disk_image": {"disk", "filesystem", "ewf"}, "memory_dump": {"memory"},
                "registry": {"registry"}, "event_log": {"evtx"}}
    if item.get("artifact_kind") == "filesystem_block_sample":
        value.update(kind="block", label=LABELS["block"], basis="Producing run: raw filesystem data units")
    elif (item.get("type_basis") == "analyst" and chosen in {"disk_image", "memory_dump"}
          and value["kind"] in ACQUISITION_CONTEXT_KINDS):
        # Raw acquisitions have no universal signature. libmagic can identify
        # incidental bytes inside them as another format; its generic MIME
        # observation must not override the recorded acquisition context.
        # Explicit forensic/document format checks above retain precedence.
        kind = "disk" if chosen == "disk_image" else "memory"
        value.update(kind=kind, label=LABELS[kind], basis="Analyst selection",
                     note="Acquisition context supplied by the analyst; native analysis validates the image.")
    elif chosen in expected and value["kind"] not in expected[chosen]:
        value["note"] = "Observed content differs from the registered type. Actions follow the observed content."
    return value
