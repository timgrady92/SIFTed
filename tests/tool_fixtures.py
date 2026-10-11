"""Synthetic, reproducible forensic inputs; no real case evidence is used."""
import re
import shutil
import struct
import subprocess

import pytest


def pdf_bytes():
    stream = b"BT /F1 18 Tf 72 720 Td (Known forensic PDF marker) Tj ET"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"]
    data = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, content in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(index).encode() + b" 0 obj\n" + content + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 6\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        data += f"{offset:010d} 00000 n \n".encode()
    data += b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"
    return bytes(data)


def make_pdf(path):
    path.write_bytes(pdf_bytes())
    return path


def make_disk(root, sector_size=512):
    mkfs = shutil.which("mkfs.ext4")
    debugfs = shutil.which("debugfs")
    if not mkfs or not debugfs:
        pytest.skip("Synthetic filesystem fixtures require mkfs.ext4 and debugfs.")
    volume = root / "synthetic volume.img"
    with volume.open("wb") as handle:
        handle.truncate(16 * 1024 * 1024)
    subprocess.run([mkfs, "-q", "-F", "-b", "1024", str(volume)], check=True, capture_output=True)
    payload = b"known_disk_content_marker\x00\xff\n" * 30
    content = root / "source content.bin"
    content.write_bytes(payload)
    pdf = make_pdf(root / "document source.pdf")
    commands = root / "debugfs commands.txt"
    commands.write_text(f'write "{content}" /known.bin\nmkdir /nested\nwrite "{pdf}" /nested/known.pdf\n')
    subprocess.run([debugfs, "-w", "-f", str(commands), str(volume)], check=True, capture_output=True)
    observed = subprocess.run([debugfs, "-R", "stat /known.bin", str(volume)], check=True, capture_output=True, text=True).stdout
    inode = re.search(r"Inode:\s*(\d+)", observed)
    block = re.search(r"\(0\):\s*(\d+)", observed)
    free = subprocess.run([debugfs, "-R", "find_free_block", str(volume)], check=True, capture_output=True, text=True).stdout
    free_block = re.search(r"Free blocks found:\s*(\d+)", free)
    assert inode and block and free_block, (observed, free)
    offset = 1024*1024 // sector_size
    header = bytearray(1024*1024)
    header[446:462] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0x83, b"\0\0\0", offset, volume.stat().st_size // sector_size)
    header[510:512] = b"\x55\xaa"
    disk = root / "synthetic disk with spaces.img"
    with disk.open("wb") as handle:
        handle.write(header)
        with volume.open("rb") as source:
            shutil.copyfileobj(source, handle)
    return {"path": disk, "offset": offset, "inode": inode[1], "block": int(block[1]),
            "free_block": int(free_block[1]), "payload": payload, "sector_size": sector_size}
