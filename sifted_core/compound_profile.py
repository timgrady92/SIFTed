"""Bounded, isolated CFB inspection using olefile's structural parser."""
import json
import resource
import sys

import olefile


def inspect(path):
    with olefile.OleFileIO(path, raise_defects=olefile.DEFECT_INCORRECT) as container:
        if not container.exists('DestList') or container.get_type('DestList') != olefile.STGTY_STREAM:
            return False
        header = container.openstream('DestList').read(32)
        if len(header) != 32 or int.from_bytes(header[:4], 'little') not in {1, 3, 4}:
            return False
        if int.from_bytes(header[4:8], 'little') == 0:
            return True
        for name in container.listdir(streams=True, storages=False):
            if len(name) == 1 and name[0] and all(c in '0123456789abcdefABCDEF' for c in name[0]):
                if container.openstream(name).read(20) == bytes.fromhex('4c0000000114020000000000c000000000000046'):
                    return True
        return False


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 ** 2, 256 * 1024 ** 2))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    try:
        print(json.dumps({'jump_list': inspect(sys.argv[1]), 'parser': 'olefile', 'version': olefile.__version__}))
    except (OSError, ValueError, IndexError, MemoryError, RecursionError):
        print(json.dumps({'jump_list': False, 'error': 'Compound structure could not be validated within profiling limits.'}))
