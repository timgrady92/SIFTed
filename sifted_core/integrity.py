"""Stable evidence reads and canonical, portable collection fingerprints."""
import hashlib
import json
import os
import stat
from pathlib import Path


class ExecutionFailure(RuntimeError):
    def __init__(self, message, code=1, status="error"):
        super().__init__(message)
        self.code, self.status = code, status


class IntegrityFailure(ExecutionFailure):
    """The input can no longer be trusted against its captured baseline."""


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def evidence_path(path):
    """Reject symlinks before normalization can hide them, including parent links."""
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Evidence paths must not contain symbolic links.")
    return str(path)


def hash_file(path, check=None):
    path = evidence_path(path)
    before = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ExecutionFailure("Evidence must be a regular file: " + path)
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise IntegrityFailure("File changed before hashing: " + path)
        while chunk := handle.read(1024 * 1024):
            if check:
                check()
            digest.update(chunk)
        if identity(os.fstat(handle.fileno())) != identity(before):
            raise IntegrityFailure("File changed while hashing: " + path)
    if identity(os.stat(path, follow_symlinks=False)) != identity(before):
        raise IntegrityFailure("File changed while hashing: " + path)
    return digest.hexdigest(), before.st_size


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def manifest_hash(entries):
    """Names, kinds, sizes and hashes; excludes host-specific inode/timestamps."""
    return hashlib.sha256(canonical({"format": "sifted-manifest-v1", "entries": sorted(entries, key=lambda e: e["path"])})).hexdigest()
