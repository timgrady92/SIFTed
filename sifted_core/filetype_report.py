"""Standalone CSV reporting around the installed file command."""
import csv
import json
import os
import subprocess
import sys
from pathlib import Path

MIME_BY_EXTENSION = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
    "pdf": "application/pdf", "zip": "application/zip", "txt": "text/plain",
    "json": "application/json", "exe": "application/x-dosexec", "dll": "application/x-dosexec",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def write_report(source, output, argv, parameters, identify=None, check=None, permitted=None):
    source = Path(source)
    if source.is_file():
        files = iter([source])
    elif parameters["recursive"]:
        files = (Path(root) / name for root, dirs, names in os.walk(source, followlinks=False)
                 for name in sorted(names))
    else:
        files = (p for p in sorted(source.iterdir()) if p.is_file())

    def native_identify(path):
        command = [str(path) if arg == "{selected_file}" else arg for arg in argv]
        result = subprocess.run(command, capture_output=True, timeout=10, check=True)
        return result.stdout.decode("utf-8", errors="replace").strip()

    identify = identify or native_identify
    count = mismatches = 0
    failures = []
    with Path(output).open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Path", "Extension", "Detected Type", "Mismatch"])
        for path in files:
            if check:
                check()
            if path.is_symlink() or not path.is_file() or permitted and not permitted(path):
                failures.append("Skipped non-regular or disallowed file: " + str(path))
                continue
            try:
                detected = identify(path)
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(str(path) + ": " + str(exc))
                continue
            ext = path.suffix.lstrip(".").lower()
            expected = MIME_BY_EXTENSION.get(ext)
            mismatch = bool(parameters["mode"] == "mime" and expected and detected != expected)
            count += 1
            mismatches += mismatch
            if not parameters["mismatch_only"] or mismatch:
                writer.writerow([str(path), ext, detected, "Yes" if mismatch else "No"])
            handle.flush()
    return {"file_count": count, "mismatch_count": mismatches}, failures


def main():
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    counts, failures = write_report(request["source"], sys.argv[2], request["argv"], request["parameters"])
    for error in failures:
        print(error, file=sys.stderr)
    print(f"Processed {counts['file_count']} files, {counts['mismatch_count']} mismatches")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
