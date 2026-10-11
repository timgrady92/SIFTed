"""Small known artifacts; external upstream hives/logs are pinned separately."""

import struct

TARGET = "known forensic target ü.txt"
DELETED_PATH = "C:\\Evidence\\known deleted target ü.txt"


def shortcut():
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 76)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<II", header, 20, 0x88, 0x80)
    struct.pack_into("<I", header, 60, 1)
    return (
        bytes(header)
        + struct.pack("<H", len(TARGET))
        + TARGET.encode("utf-16-le")
        + b"\0\0\0\0"
    )


def custom_jump_list():
    return struct.pack("<IfII", 2, 1.0, 0, 1) + shortcut() + b"\xab\xfb\xbf\xba"


def recycle_bin(version=2):
    data = struct.pack("<QQQ", version, 1024, 133485408000000000)
    if version == 2:
        return (
            data
            + struct.pack("<I", len(DELETED_PATH) + 1)
            + (DELETED_PATH + "\0").encode("utf-16-le")
        )
    return data + (DELETED_PATH + "\0").encode("utf-16-le").ljust(520, b"\0")


def recent_cache():
    return (
        b"\xfe\xff\xee\xff"
        + b"\0" * 16
        + struct.pack("<I", len(DELETED_PATH))
        + (DELETED_PATH + "\0").encode("utf-16-le")
    )


def hive_header(dirty=False):
    header = bytearray(512)
    header[:4] = b"regf"
    struct.pack_into("<II", header, 4, 2 if dirty else 1, 1)
    return bytes(header)


def event_header():
    header = bytearray(4096)
    header[:8] = b"ElfFile\0"
    struct.pack_into("<IHHHH", header, 32, 128, 1, 3, 4096, 0)
    return bytes(header)


PUBLIC_FIXTURES = {
    "Amcache.hve": "4e574ac939d423947701302bc35d9a0da0b669a5fb86dbf8157a46c6f38f2c6d",
    "System.evtx": "d67fe3d1c56e0dcdd4c0d8d3512f74dd500cc2bff52686a0be52b182547e6470",
    "SYSTEM": "ec01a4ec205c5354a4ad1d5d088f45e2331ffb13773dcc7008e6ea6f2175466f",
    "NTUSER.DAT": "8d5fdee75d69b878a0bf602f7a15f0410c5622b9c8c84a5c2f346d44a8cdb759",
    "UsrClass.dat": "232a03165b46650f1c0705d917e50eb867fe3db1a342d032e68cd5ea1d2f0870",
    "automatic.automaticDestinations-ms": "3c1798afe43e6d3ddad8654e5dc498f21f3c7be9ec69ebf3c9002637d94c0166",
    "f01b4d95cf55d32a.automaticDestinations-ms": "a724713d2ff51d32e3f028c57ab906339f882de0c93dc9903f0f8b241c53fd56",
    "replay-NTUSER.DAT": "e47f18fb696e4f18ff7432348561e4393f20336b80d0dd88e9c134e5575ecae1",
    "replay-NTUSER.DAT.log1": "da74b301d70d460a901b533410409143e0fbb71b9f9ed50a1b18f80f6163896b",
    "replay-NTUSER.DAT.log2": "46104b07952e0b31146cb383f3d4e127e182c4bc375ca647385a58674fd3be53",
}
