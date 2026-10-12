"""Read-only structural probes, executed with the workstation's native Python.

No application imports or added forensic dependencies. stdout is a small JSON
record; the shared worker owns process lifetime, cancellation and publication.
"""
import bisect
import hashlib
import json
from pathlib import Path
import resource
import struct
import sys


def identity(module, version):
    path = Path(module.__file__).resolve()
    with path.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    return {'name': module.__name__, 'version': str(version), 'path': str(path), 'sha256': digest}


def disk(paths):
    import pytsk3

    parsers = [identity(pytsk3, pytsk3.get_version())]
    with open(paths[0], 'rb') as source:
        ewf = source.read(8) in (b'EVF\x09\x0d\x0a\xff\x00', b'EVF2\x0d\x0a\x81\x00')
    handles, ends, total = [], [], 0
    container = None
    try:
        if ewf:
            import pyewf
            parsers.append(identity(pyewf, pyewf.get_version()))
            container = pyewf.handle()
            container.open(paths)
            total = container.get_media_size()
        else:
            for path in paths:
                handle = open(path, 'rb')
                handles.append(handle)
                total += Path(path).stat().st_size
                ends.append(total)

        class VerifiedImage(pytsk3.Img_Info):
            """Expose only the exact, already verified collection to libtsk."""
            def __init__(self):
                super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def read(self, offset, size):
                if container:
                    container.seek(offset)
                    return container.read(size)
                chunks = []
                while size > 0 and offset < total:
                    index = bisect.bisect_right(ends, offset)
                    start = ends[index - 1] if index else 0
                    handles[index].seek(offset - start)
                    data = handles[index].read(min(size, ends[index] - offset))
                    if not data:
                        break
                    chunks.append(data)
                    offset, size = offset + len(data), size - len(data)
                return b''.join(chunks)

            def get_size(self):
                return total

            def close(self):
                pass  # Backing resources are owned by the surrounding try/finally.

        facts = {'media_size': total, 'tsk_version': pytsk3.TSK_VERSION_STR}
        image = VerifiedImage()
        try:
            volume = pytsk3.Volume_Info(image)
            parts = []
            for index, part in enumerate(volume):
                if index >= 1024:
                    raise ValueError('Partition table exceeds profiling limits.')
                if part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    if part.start < 0 or part.len <= 0 or (part.start + part.len) * volume.info.block_size > total:
                        raise ValueError('Partition exceeds the image.')
                    parts.append({'start': part.start, 'length': part.len})
            if parts:
                facts.update(sector_size=volume.info.block_size, partitions=parts, volume_type=int(volume.info.vstype))
                return {'status': 'matched', 'kind': 'ewf' if ewf else 'disk', 'facts': facts, 'parsers': parsers}
        except (OSError, ValueError):
            pass
        try:
            fs = pytsk3.FS_Info(image)
            if fs.info.block_size > 0 and 0 < fs.info.block_count * fs.info.block_size <= total:
                facts.update(filesystem_type=int(fs.info.ftype), block_size=fs.info.block_size, block_count=fs.info.block_count)
                return {'status': 'matched', 'kind': 'ewf' if ewf else 'filesystem', 'facts': facts, 'parsers': parsers}
        except OSError:
            pass
        if ewf and total > 0:
            return {'status': 'matched', 'kind': 'ewf', 'facts': facts, 'parsers': parsers}
        return {'status': 'no_match', 'parsers': parsers}
    finally:
        for handle in handles:
            handle.close()
        if container:
            container.close()


def memory(path, location):
    sys.path.insert(0, location)
    from volatility3.framework import contexts, constants, exceptions
    from volatility3.framework.automagic import windows
    from volatility3.framework.layers import physical, crash, lime, elf

    constants.OFFLINE = True
    context = contexts.Context()
    context.config['capture.location'] = Path(path).as_uri()
    base = physical.FileLayer(context, 'capture', 'capture')
    context.add_layer(base)
    parsers = [identity(windows, constants.PACKAGE_VERSION)]
    container_kind = None
    for module, stacker in ((crash, crash.WindowsCrashDumpStacker), (lime, lime.LimeStacker), (elf, elf.Elf64Stacker)):
        try:
            layer = stacker.stack(context, base.name)
        except (exceptions.LayerException, ValueError, OSError):
            continue
        if layer:
            context.add_layer(layer)
            base = layer
            parsers.append(identity(module, constants.PACKAGE_VERSION))
            container_kind = module.__name__.rsplit('.', 1)[-1]
            break
    facts = {'container': container_kind or 'raw'}
    layer = windows.WindowsIntelStacker.stack(context, base.name)
    if layer:
        # Corroborate a candidate DTB through actual address translation. These
        # KUSER_SHARED_DATA fields have fixed layouts independent of PDB symbols.
        address = 0xffdf0000 if layer.bits_per_register == 32 else 0xfffff78000000000
        try:
            major, minor = struct.unpack('<II', layer.read(address + 0x26c, 8))
            root = layer.read(address + 0x30, 520).decode('utf-16-le').split('\0')[0]
            if major in {3, 4, 5, 6, 10} and minor <= 3 and len(root) >= 4 and root[1:3] == ':\\':
                facts.update(os='windows', architecture=layer.metadata['architecture'],
                             page_map_offset=layer.config['page_map_offset'], nt_major=major, nt_minor=minor, system_root=root)
                return {'status': 'matched', 'kind': 'memory', 'facts': facts, 'parsers': parsers}
        except (exceptions.InvalidAddressException, UnicodeError, ValueError):
            pass
    # Container structure itself can establish physical memory even when kernel
    # pages are absent. ELF core alone could be a process dump, so is inconclusive.
    if container_kind in {'crash', 'lime'}:
        if container_kind == 'crash':
            facts['os'] = 'windows'
        return {'status': 'matched', 'kind': 'memory', 'facts': facts, 'parsers': parsers}
    return {'status': 'no_match', 'parsers': parsers}


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    try:
        if sys.argv[1] == 'disk':
            result = disk(json.loads(sys.argv[2]))
        else:
            result = memory(sys.argv[2], sys.argv[3])
    except ImportError as exc:
        result = {'status': 'unavailable', 'detail': str(exc)}
    except (OSError, ValueError, RuntimeError, MemoryError) as exc:
        result = {'status': 'inconclusive', 'detail': str(exc)[:500]}
    print(json.dumps(result))
