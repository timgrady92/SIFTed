"""Deterministic, independently specified carving fixtures; no downloaded images."""

import io
import struct
import zipfile
import zlib
from pathlib import Path

from tool_fixtures import pdf_bytes


def samples():
    def chunk(kind, data):
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data))
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0"))
        + chunk(b"IEND", b"")
    )
    gif = bytes.fromhex(
        "47494638396101000100800000ff00000000002c00000000010001000002024401003b"
    )
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        member = zipfile.ZipInfo("known.txt", date_time=(2026, 1, 1, 0, 0, 0))
        handle.writestr(member, b"known recovered archive content")
    pdf = pdf_bytes()
    bmp = (
        b"BM"
        + struct.pack("<IHHI", 102, 0, 0, 54)
        + struct.pack("<IiiHHIIiiII", 40, 4, 4, 1, 24, 0, 48, 0, 0, 0, 0)
        + b"\0\0\xff" * 16
    )
    pe = bytearray(1024)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 60, 128)
    pe[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 132, 0x14C, 1, 1767225600, 0, 0, 224, 0x102)
    struct.pack_into("<H", pe, 152, 0x10B)
    struct.pack_into("<I", pe, 156, 512)
    struct.pack_into("<I", pe, 168, 4096)
    struct.pack_into("<IIII", pe, 176, 4096, 0x400000, 4096, 512)
    struct.pack_into("<II", pe, 208, 8192, 512)
    struct.pack_into("<H", pe, 220, 3)
    struct.pack_into("<I", pe, 244, 16)
    pe[376:384] = b".text\0\0\0"
    struct.pack_into("<IIII", pe, 384, 1, 4096, 512, 512)
    struct.pack_into("<I", pe, 412, 0x60000020)
    pe[512] = 0xC3
    return {
        "jpg": (Path(__file__).parent / "samples/images/geotagged.jpg").read_bytes(),
        "png": png,
        "gif": gif,
        "pdf": pdf,
        "zip": archive.getvalue(),
        "bmp": bmp,
        "exe": bytes(pe),
    }


def mixed_image(path, types=("jpg", "png", "gif", "pdf", "zip"), duplicate=True):
    values = samples()
    image = bytearray(b"\0" * 512)
    expected = []
    for kind in types:
        expected.append((kind, len(image), values[kind]))
        image += values[kind] + b"\0" * 1024
    if duplicate:
        # Two same-type headers in one naming block: neither file may be overwritten.
        image += b"\0" * ((512 - len(image) % 512) % 512)
        for _ in range(2):
            expected.append(("png", len(image), values["png"]))
            image += values["png"] + b"\0" * 8
    image += b"\0" * 512
    path.write_bytes(image)
    return expected
