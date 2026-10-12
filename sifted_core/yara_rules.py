"""Pinned application resources, saved through ordinary configuration provenance."""
import hashlib
import json
from pathlib import Path

from .tool_base import ValidationError

LIBRARY = Path(__file__).resolve().parents[1] / 'rules/yara'
DEFAULT_RULES = LIBRARY / 'memory.yar'


def snapshot(path):
    """Only the exact shipped file is an application resource, not an input root."""
    candidate = Path(path).expanduser().absolute()
    if candidate != DEFAULT_RULES and candidate.resolve() != DEFAULT_RULES:
        return None
    try:
        def read(name, digest=None):
            file = LIBRARY / name
            if file.resolve() != file or not file.is_relative_to(LIBRARY) or '..' in file.parts:
                raise ValueError('Rule library paths must not contain links or traversal.')
            data = file.read_bytes()
            if len(data) > 4 * 1024 * 1024 or digest is not None and hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Rule library digest does not match its manifest.')
            return data.decode('utf-8')

        metadata = read('manifest.json')
        manifest = json.loads(metadata)
        if manifest['format'] != 1 or manifest['bundle']['path'] != 'memory.yar':
            raise ValueError('Unsupported rule library manifest.')
        content = read('memory.yar', manifest['bundle']['sha256'])
        configs = {'yara/memory.yar': content, 'yara/manifest.json': metadata}
        for source in manifest['sources']:
            configs['yara/' + source['license_path']] = read(source['license_path'], source['license_sha256'])
        return configs, {'id': manifest['id'], 'version': manifest['version'], 'label': manifest['label'],
                         'path': str(DEFAULT_RULES), 'sha256': manifest['bundle']['sha256'],
                         'rule_count': manifest['rule_count'], 'sources': [s['name'] for s in manifest['sources']]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValidationError('Bundled YARA library is unavailable or changed; restore it or select a custom rule file.') from exc
