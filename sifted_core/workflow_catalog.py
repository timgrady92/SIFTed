"""Form metadata for disk analysis and bounded file examination."""
from .disk_tools import DISK_TOOL_IDS
from .examination_tools import EXAMINATION_TOOL_IDS


def number(name, label, default=0, minimum=0, maximum=2**53 - 1):
    return {"name": name, "label": label, "type": "number", "default": default, "min": minimum, "max": maximum}


GEOMETRY = [number("offset_sector", "Filesystem offset (disk sectors)"),
            {"name": "sector_size", "label": "Disk sector size", "type": "select", "default": "",
             "choices": [("", "Auto-detect (raw images default to 512 bytes)"), (512, "512 bytes"),
                         (1024, "1024 bytes"), (2048, "2048 bytes"), (4096, "4096 bytes")]}]
METADATA = {"name": "metadata_address", "label": "Inode / NTFS metadata address", "type": "text", "default": "", "placeholder": "42 or 42-128-1"}
BLOCK = number("block_address", "Filesystem data-unit address")
DETAILS = {
    "clamscan": ("Check local malware signatures", "Scan captured files with the installed ClamAV signatures. A match needs corroboration; no matches do not prove safety. Files are never executed, removed or uploaded.", []),
    "mmls": ("Map partitions", "Find the disk sectors where each partition begins.", [GEOMETRY[1]]),
    "fsstat": ("Describe filesystem", "Read filesystem type, geometry, allocation ranges, and metadata.", GEOMETRY),
    "fls": ("Browse files", "List names and metadata addresses; deleted names are observations, not proof of recoverable content.", GEOMETRY +
            [{"name": "directory_inode", "label": "Directory metadata address (blank for root)", "type": "text", "default": ""},
             {"name": "recursive", "label": "Recursive inventory with paths", "type": "checkbox", "default": False},
             {"name": "deleted_only", "label": "Deleted entries only", "type": "checkbox", "default": False}]),
    "istat": ("Inspect file metadata", "Inspect the inode or MFT record. NTFS stream suffixes are removed only for this metadata inspection.", GEOMETRY + [METADATA]),
    "icat": ("Extract file content", "Preserve the selected file or NTFS stream as a hashed artifact. Deleted-file recovery may be incomplete.", GEOMETRY + [METADATA,
             {"name": "entry_name", "label": "Extracted filename", "type": "text", "default": "extracted.bin"},
             {"name": "recover_deleted", "label": "Attempt deleted-file recovery", "type": "checkbox", "default": False}]),
    "blkstat": ("Check block allocation", "Observe allocation state for one filesystem data unit. Its address is not a disk-sector offset.", GEOMETRY + [BLOCK]),
    "blkcat": ("Extract a block", "Capture exactly one filesystem data unit as binary bytes (maximum 1 MiB).", GEOMETRY + [BLOCK]),
    "blkls": ("Sample unallocated blocks", "Capture unallocated units in a selected range, up to 1,024 units and 1 MiB. Allocated units are excluded.", GEOMETRY + [BLOCK,
              number("end_block", "Last filesystem data unit (blank for one unit)", "")]),
    "blkcalc": ("Map block addresses", "Convert between original filesystem data-unit addresses and ordinals in a complete unallocated stream. A targeted blkls sample is not that complete stream.", GEOMETRY + [BLOCK,
                {"name": "direction", "label": "Mapping direction", "type": "select", "default": "unallocated_to_original",
                 "choices": [("unallocated_to_original", "Unallocated stream → original filesystem"),
                             ("original_to_unallocated", "Original filesystem → unallocated stream")]}]),
    "head": ("Read a text sample", "Read up to 64 KiB without executing or opening the file in its native application.", [number("byte_limit", "Bytes to read", 65536, 1, 65536)]),
    "xxd": ("Inspect hexadecimal bytes", "Show hexadecimal bytes and their offsets, up to 64 KiB per examination.",
            [number("byte_offset", "Starting byte offset"), number("byte_limit", "Bytes to examine", 4096, 1, 65536)]),
    "pdfinfo": ("Read PDF properties", "Read document metadata from a content-identified PDF; the PDF is not rendered.", []),
    "pdftotext": ("Extract PDF text", "Extract text from selected pages (at most the first 50 pages); scans without a text layer need OCR separately.",
                  [number("first_page", "First page", 1, 1, 50), number("last_page", "Last page", 5, 1, 50)]),
}
WORKFLOWS = {tool: {"id": tool, "label": title, "description": description, "fields": fields,
                    "category": "Disk Analysis" if tool in DISK_TOOL_IDS else "File Examination"}
             for tool, (title, description, fields) in DETAILS.items()}
CATEGORIES = {"disk-analysis": DISK_TOOL_IDS, "file-examination": (*EXAMINATION_TOOL_IDS, "clamscan")}
