"""Read-only Sleuth Kit plans with explicit geometry and safe extracted names."""
from pathlib import Path
import re

from .tool_base import OUTPUT, Plan, Step, ToolAdapter, ValidationError, executable, flag, integer, text


DISK_TOOL_IDS = ("mmls", "fsstat", "fls", "istat", "icat", "blkstat", "blkcat", "blkls", "blkcalc")
MAX_SAMPLE_BYTES = 1024 * 1024


def metadata_address(payload, key="metadata_address", optional=False):
    value = text(payload, key)
    if not value and optional:
        return None
    if not re.fullmatch(r"\d{1,20}(?:-\d{1,20}){0,2}", value) or any(int(v) > 2**64 - 1 for v in value.split("-")):
        raise ValidationError(f"{key} must be an inode or NTFS metadata address such as 42-128-1.")
    return value


def image_sources(source):
    """Snapshot all members of conventional raw/EWF segmented image sequences.

    TSK can discover siblings implicitly. Enumerating them here makes each
    segment an explicit, hash-verified input rather than an invisible dependency.
    """
    path = Path(source)
    match = re.fullmatch(r"(.*)\.(\d{3}|[eE](?:[xX])?[0-9a-zA-Z]{2})", path.name)
    if not match or source == "<source_path>":
        return [source]
    prefix, extension = match.groups()
    numeric = extension.isdigit()
    sequence = re.compile(re.escape(prefix) + (r"\.(\d{3})" if numeric else r"\.([eE](?:[xX])?[0-9a-zA-Z]{2})"))

    def ordinal(ext):
        if numeric:
            return int(ext)
        suffix = ext[-2:].upper()
        if suffix.isdigit():
            return int(suffix)
        if suffix.isalpha():
            return 100 + (ord(suffix[0]) - ord("A")) * 26 + ord(suffix[1]) - ord("A")
        raise ValidationError("Invalid EWF segment sequence.")

    members = []
    for candidate in path.parent.iterdir():
        found = sequence.fullmatch(candidate.name)
        if found and (numeric or found.group(1)[:-2].casefold() == extension[:-2].casefold()):
            if candidate.is_symlink() or not candidate.is_file():
                raise ValidationError("Image segments must be regular files without symbolic links.")
            members.append((ordinal(found.group(1)), str(candidate.resolve())))
    members.sort()
    if not members or members[0][1] != source:
        raise ValidationError("Select the first image segment (.001 or .E01/.Ex01).")
    start = 0 if numeric and members[0][0] == 0 else 1
    if [index for index, _ in members] != list(range(start, start + len(members))):
        raise ValidationError("Image segment sequence contains a gap or duplicate.")
    return [name for _, name in members]


class DiskAdapter(ToolAdapter):
    def __init__(self, tool_id):
        self.tool_id = tool_id
        self.parameter_names = {"sector_size", "context_run_id"}
        if tool_id != "mmls":
            self.parameter_names |= {"offset_sector"}
        self.parameter_names |= {
            "fls": {"directory_inode", "recursive", "deleted_only"},
            "istat": {"metadata_address"},
            "icat": {"metadata_address", "entry_name", "recover_deleted"},
            "blkstat": {"block_address"}, "blkcat": {"block_address"},
            "blkls": {"block_address", "end_block"}, "blkcalc": {"block_address", "direction"},
        }.get(tool_id, set())

    def build(self, p, source, output, settings, preview=False):
        tool = self.tool_id
        args = executable(tool, [tool], settings, not preview)
        params = {}
        sector_size = p.get("sector_size")
        if sector_size is not None:
            sector_size = integer(p, "sector_size")
            if sector_size not in {512, 1024, 2048, 4096}:
                raise ValidationError("sector_size must be 512, 1024, 2048, or 4096 bytes.")
            args += ["-b", str(sector_size)]
            params["sector_size"] = sector_size
        if tool == "mmls":
            args += ["-B"]
        else:
            offset = integer(p, "offset_sector", 0)
            args += ["-o", str(offset)]
            params["offset_sector"] = offset
        tail = []
        filename = tool + ".txt"
        max_stdout = None
        postprocess = tool if tool in {"mmls", "fls", "blkstat", "blkcalc", "icat", "blkcat", "blkls"} else None
        if tool == "fls":
            recursive = flag(p, "recursive")
            deleted = flag(p, "deleted_only")
            if recursive:
                args += ["-r", "-p"]
            if deleted:
                args += ["-d"]
            directory = metadata_address(p, "directory_inode", optional=True)
            if directory:
                tail.append(directory)
            params.update(directory_inode=directory, recursive=recursive, deleted_only=deleted)
        elif tool in {"istat", "icat"}:
            address = metadata_address(p)
            params["metadata_address"] = address
            # istat examines the metadata record; icat must preserve NTFS stream IDs.
            tail = [address.split("-", 1)[0] if tool == "istat" else address]
            if tool == "icat":
                name = text(p, "entry_name", "extracted.bin")
                if not name or name in {".", ".."} or any(c in name for c in "/\\\x00") or len(name.encode()) > 255 or name == "_sifted":
                    raise ValidationError("entry_name must be a safe filename without directory components (maximum 255 bytes).")
                filename = name
                recovery = flag(p, "recover_deleted")
                if recovery:
                    args += ["-r"]
                params.update(entry_name=name, recover_deleted=recovery)
        elif tool.startswith("blk"):
            address = integer(p, "block_address")
            params["block_address"] = address
            tail = [str(address)]
            if tool == "blkcat":
                tail += ["1"]
            elif tool == "blkls":
                end = integer(p, "end_block", address, minimum=address, maximum=min(2**53 - 1, address + 1023))
                args += ["-A"]
                tail = [f"{address}-{end}"]
                params["end_block"] = end
            elif tool == "blkcalc":
                direction = text(p, "direction", "unallocated_to_original")
                if direction not in {"original_to_unallocated", "unallocated_to_original"}:
                    raise ValidationError("Unsupported block mapping direction.")
                args += ["-d" if direction == "original_to_unallocated" else "-u", str(address)]
                tail = []
                params["direction"] = direction
            if tool in {"blkcat", "blkls"}:
                filename = tool + ".bin"
                max_stdout = MAX_SAMPLE_BYTES
        paths = image_sources(source)
        args += paths + tail
        steps = [Step(args, tool, OUTPUT + "/" + filename, settings.timeout_seconds, max_stdout_bytes=max_stdout)]
        if tool == "blkcalc" and params["direction"] == "original_to_unallocated":
            # TSK builds differ in the index base reported by blkcalc -d.
            # Verify against the actual ordered unallocated units, retaining
            # both raw reports and never silently assuming a numeric convention.
            verify = executable("blkls", ["blkls"], settings, not preview) + ["-A", "-l", "-o", str(params["offset_sector"])]
            if sector_size is not None:
                verify += ["-b", str(sector_size)]
            verify += paths + [f"0-{params['block_address']}"]
            steps.append(Step(verify, "Verify unallocated stream position", OUTPUT + "/mapping_units.txt", settings.timeout_seconds))
        return Plan(tool, source, output,
                    steps,
                    parameters=params, expected_files=[filename], postprocess=postprocess, input_paths=paths)
