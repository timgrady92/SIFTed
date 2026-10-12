"""Read published artifacts through their verified descriptor and manifest.

Views and selections use the same boundary: complete run, allowed path, stable
bytes and the recorded digest. A result filename alone never authorizes input.
"""
from contextlib import contextmanager
import csv
import hashlib
import io
import json
import os
import stat
from pathlib import Path

from .integrity import evidence_path, identity
from .json_rows import json_lines, tree_rows
from .tool_base import ValidationError, allowed


@contextmanager
def artifact(run, name, repository, settings, max_bytes=1024 ** 3):
    if not run or run['status'] != 'success':
        raise ValidationError('A complete successful result is required.')
    entry = next((x for x in repository.artifacts(run['id']) if x['name'] == name and x.get('complete')), None)
    if not entry or not allowed(entry['path'], settings.output_roots):
        raise ValidationError('Result has no complete manifest or is outside allowed roots.')
    try:
        path = evidence_path(entry['path'])
        if Path(path) != Path(run['output_path']) / name:
            raise ValidationError('Result path does not match its producing run.')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
            before = identity(os.fstat(handle.fileno()))
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode) or before[2] > max_bytes:
                raise ValidationError('Result is not a regular file within the reading limit.')
            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            if digest.hexdigest() != entry['sha256'] or identity(os.fstat(handle.fileno())) != before:
                raise ValidationError('Published result changed; rerun the examination before using it.')
            handle.seek(0)
            yield handle
            if identity(os.fstat(handle.fileno())) != before or identity(os.stat(path, follow_symlinks=False)) != before:
                raise ValidationError('Published result changed while reading.')
    except (OSError, ValueError, csv.Error) as exc:
        raise ValidationError(str(exc)) from exc


def records(handle, name):
    """Preserve typed values and all tree rows across structured renderers."""
    if name.endswith('.jsonl'):
        for root in json_lines(handle):
            yield from tree_rows([root])
    elif name.endswith('.json'):
        data = handle.read(64 * 1024 ** 2 + 1)
        if len(data) > 64 * 1024 ** 2:
            raise ValueError('JSON result exceeds 64 MiB; use JSON Lines for larger results.')
        roots = json.loads(data)
        if not isinstance(roots, list):
            raise ValueError('Structured result must contain rows.')
        yield from tree_rows(roots)
    elif name.endswith('.csv'):
        wrapper = io.TextIOWrapper(handle, encoding='utf-8-sig', newline='')
        try:
            yield from csv.DictReader(wrapper)
        finally:
            wrapper.detach()
    else:
        raise ValueError('Choose a structured result.')


def page(run, name, repository, settings, *, offset=0, query='', selected=None, limit=50):
    if offset < 0 or len(query) > 256 or (selected is not None and selected < 1):
        raise ValidationError('Choose a valid result page, row and search of at most 256 characters.')
    rows, columns, total, chosen = [], [], 0, None
    with artifact(run, name, repository, settings) as handle:
        for ordinal, row in enumerate(records(handle, name), 1):
            if ordinal == selected:
                chosen = {'id': ordinal, 'values': row}
            for key in row:
                if key != '__depth' and key not in columns:
                    columns.append(key)
            if query.casefold() not in ' '.join(str(v) for v in row.values()).casefold():
                continue
            if offset <= total < offset + limit:
                rows.append({'id': ordinal, 'values': row})
            total += 1
    if selected is not None and not chosen:
        raise ValidationError('Selected row does not belong to this result.')
    return {'rows': rows, 'columns': columns, 'total': total, 'offset': offset,
            'more': total > offset + len(rows), 'selected': chosen, 'query': query}
