#!/usr/bin/env python3
"""Reproduce the reviewed offline bundle; downloading requires explicit --fetch.

To change membership or revisions, review the upstream files and update the
manifest first. This command never follows branch heads or runs upstream code.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1] / 'rules/yara'


def build(root=ROOT, *, fetch=False, check=False):
    manifest_path = root / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    sources = {source['id']: source for source in manifest['sources']}

    def read(path, expected, source, upstream):
        local = root / path
        if local.resolve() != local or not local.is_relative_to(root) or '..' in local.parts:
            raise ValueError('Rule resources must stay inside the library.')
        if fetch:
            repository = source['repository'].removeprefix('https://github.com/')
            if repository == source['repository'] or len(repository.split('/')) != 2:
                raise ValueError('Expected a pinned GitHub source.')
            url = f"https://raw.githubusercontent.com/{repository}/{source['commit']}/{quote(upstream)}"
            with urlopen(url, timeout=30) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f'Upstream digest changed: {upstream}')
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
        data = local.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'Resource digest changed: {path}')
        return data.decode('utf-8')

    chunks = ['// SIFTed memory indicators. Sources and licenses: manifest.json and licenses/.\n'
              '// Rebuild with scripts/build_yara_bundle.py; upstream rule bodies are unchanged.\n']
    for source in sources.values():
        read(source['license_path'], source['license_sha256'], source, source['license_upstream_path'])
    for entry in manifest['files']:
        source = sources[entry['source']]
        content = read(entry['path'], entry['sha256'], source, entry['upstream_path'])
        chunks.append(f"// Source: {source['repository']}/blob/{source['commit']}/{quote(entry['upstream_path'])}\n"
                      + content.replace('\r\n', '\n').rstrip() + '\n')
    data = '\n'.join(chunks).encode('utf-8')
    bundle = {'path': 'memory.yar', 'sha256': hashlib.sha256(data).hexdigest()}
    if check:
        if manifest.get('bundle') != bundle or (root / bundle['path']).read_bytes() != data:
            raise ValueError('Bundle does not match the reviewed source manifest; rebuild it.')
    else:
        (root / bundle['path']).write_bytes(data)
        manifest['bundle'] = bundle
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print(f"{manifest['rule_count']} rules · {len(manifest['files'])} source files · SHA-256 {bundle['sha256']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', help='Fetch only the pinned, digest-verified upstream files.')
    parser.add_argument('--check', action='store_true', help='Check reproducibility without rewriting the bundle.')
    args = parser.parse_args()
    build(fetch=args.fetch, check=args.check)
