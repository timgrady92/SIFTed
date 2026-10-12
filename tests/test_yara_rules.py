"""Shipped rules are reproducible resources; custom files remain verified inputs."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from scripts.build_yara_bundle import build
from sifted_core import yara_rules
from sifted_core.adapters import compile_plan
from sifted_core.terminal import recipe
from sifted_core.tool_base import ValidationError, WORKSPACE, resolve_argv
from sifted_core.worker import Worker
from test_evidence_workspace import view
from test_memory_workspace import memory_workspace as memory_workspace, inventory, selected
from test_volatility import memory_runtime as memory_runtime, option


def payload(runtime, path):
    run = inventory(runtime)
    action = next(a for a in selected(runtime, run)['memory']['process_actions'] if a['id'] == 'rules')
    return {**action['payload'], 'plugin_options': {action['plugin']: {'pid': [42], 'yara_file': str(path)}}}


def test_shipped_bundle_is_reproducible_and_licensed():
    build(check=True)
    configs, info = yara_rules.snapshot(str(yara_rules.DEFAULT_RULES))
    manifest = json.loads(configs['yara/manifest.json'])
    assert info['sha256'] == hashlib.sha256(configs['yara/memory.yar'].encode()).hexdigest()
    assert info['rule_count'] == sum(len(f['rules']) for f in manifest['files'])
    assert set(info['sources']) == {'Google GCTI', 'Mandiant', 'ESET'}
    for source in manifest['sources']:
        assert len(source['commit']) == 40
        assert configs['yara/' + source['license_path']]


def test_bundled_rules_use_shared_snapshots_and_native_terminal_paths(memory_workspace):
    _, client, repo, settings, _, case, key, _ = memory_workspace
    data = payload(memory_workspace, yara_rules.DEFAULT_RULES)
    plan, _, record = compile_plan('volatility', data, settings, repo, preview=True)
    assert not plan.auxiliary_paths and not record.get('related_files')
    argv = resolve_argv(plan.steps[0].argv, '/results', '/working directory')
    assert argv[argv.index('--yara-file') + 1] == '/working directory/yara/memory.yar'
    cli = recipe(plan, settings)['terminal_command']
    assert '--yara-file ' + str(yara_rules.DEFAULT_RULES) in cli and WORKSPACE not in cli
    response = client.post('/api/volatility/run', json=data)
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    run = repo.run(response.json['run_id'])
    assert run['status'] == 'success', run.get('error')
    saved = Path(run['output_path']) / '_sifted/yara'
    assert (saved / 'memory.yar').read_bytes() == yara_rules.DEFAULT_RULES.read_bytes()
    assert (saved / 'manifest.json').read_bytes() == (yara_rules.LIBRARY / 'manifest.json').read_bytes()
    assert len(list((saved / 'licenses').iterdir())) == 3
    assert repo.input(run['id'])['process_selection']['pid'] == 42
    html = client.get(f'/api/case/{case}/workspace/run/{run["id"]}', query_string={'input': key}).json['html']
    assert 'Rules used' in html and 'Sources and hashes' in html
    assert client.get('/view-file', query_string={'path': str(saved / 'memory.yar')}).status_code == 200


@pytest.mark.parametrize('mode', ['missing', 'changed', 'symlink', 'license', 'manifest'])
def test_damaged_library_cannot_be_silently_used(tmp_path, monkeypatch, mode):
    root = tmp_path / 'packaged rules'
    shutil.copytree(yara_rules.LIBRARY, root)
    monkeypatch.setattr(yara_rules, 'LIBRARY', root)
    monkeypatch.setattr(yara_rules, 'DEFAULT_RULES', root / 'memory.yar')
    if mode == 'missing':
        (root / 'memory.yar').unlink()
    elif mode == 'symlink':
        data = (root / 'memory.yar').read_bytes()
        (root / 'memory.yar').unlink()
        (tmp_path / 'outside.yar').write_bytes(data)
        (root / 'memory.yar').symlink_to(tmp_path / 'outside.yar')
    elif mode == 'license':
        (root / 'licenses/eset.txt').write_text('changed')
    elif mode == 'manifest':
        (root / 'manifest.json').write_text('{}')
    else:
        (root / 'memory.yar').write_text('rule changed { condition: true }')
    with pytest.raises(ValidationError, match='Bundled YARA library'):
        yara_rules.snapshot(str(root / 'memory.yar'))


def test_queued_bundle_keeps_its_reviewed_bytes_after_library_update(memory_workspace, monkeypatch, tmp_path):
    _, client, repo, settings, *_ = memory_workspace
    root = tmp_path / 'application rules'
    shutil.copytree(yara_rules.LIBRARY, root)
    monkeypatch.setattr(yara_rules, 'LIBRARY', root)
    monkeypatch.setattr(yara_rules, 'DEFAULT_RULES', root / 'memory.yar')
    data = payload(memory_workspace, root / 'memory.yar')
    response = client.post('/api/volatility/run', json=data)
    assert response.status_code == 202, response.json
    original = (root / 'memory.yar').read_bytes()
    (root / 'memory.yar').write_text('rule replacement { condition: true }')
    assert client.post('/api/volatility/preview', json=data).status_code == 400
    Worker(repo, settings).run_once()
    run = repo.run(response.json['run_id'])
    assert run['status'] == 'success', run.get('error')
    assert (Path(run['output_path']) / '_sifted/yara/memory.yar').read_bytes() == original


def test_library_does_not_expand_input_roots_or_allow_competing_rule_sources(memory_workspace):
    _, client, _, _, source, _, _, installed = memory_workspace
    data = payload(memory_workspace, yara_rules.LIBRARY / 'licenses/eset.txt')
    assert client.post('/api/volatility/run', json=data).status_code == 400
    plugin = data['plugins'][0]
    installed['plugins'][plugin]['options'] += [option('yara_string', 'string'), option('yara_compiled_file', 'file')]
    data['plugin_options'][plugin].update(yara_file=str(yara_rules.DEFAULT_RULES), yara_string='test')
    assert client.post('/api/volatility/run', json=data).status_code == 400
    del data['plugin_options'][plugin]['yara_file']
    data.pop('process_ref')  # Inline patterns belong to the standalone examiner.
    assert client.post('/api/volatility/preview', json=data).status_code == 200
    custom = source.parent / 'custom.yar'
    custom.write_text('rule custom { condition: true }')
    data['plugin_options'][plugin] = {'pid': [42], 'yara_file': str(custom)}
    response = client.post('/api/volatility/run', json=data)
    assert response.status_code == 202
    custom.write_text('rule changed { condition: false }')
    repo, settings = memory_workspace[2:4]
    Worker(repo, settings).run_once()
    assert repo.run(response.json['run_id'])['status'] == 'error'


@pytest.mark.parametrize('os', ['windows', 'linux', 'mac'])
def test_guided_scan_prefills_rules_for_every_os(memory_workspace, os):
    _, client, _, _, _, case, key, _ = memory_workspace
    model = view(client, case, key, memory_os=os, tab='investigate', memory_question='indicators')['memory']
    action = next(a for a in model['investigations'] if a['id'] == 'rules')
    field = action['fields'][0]
    assert field['default'] == str(yara_rules.DEFAULT_RULES)
    data = action['payload']
    data['plugin_options'][action['plugin']]['yara_file'] = field['default']
    assert client.post('/api/volatility/preview', json=data).status_code == 200
