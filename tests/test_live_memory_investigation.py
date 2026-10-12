"""Native SIFT investigation using public acquisitions; no extracted code runs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from app import create_app
from sifted_core import published
from sifted_core.memory_catalog import PROFILES
from sifted_core.storage import Repository
from sifted_core.tool_base import resolve_argv
from sifted_core.volatility import discover
from sifted_core.worker import Worker
from test_evidence_workspace import register, view


@pytest.mark.live
def test_native_windows_investigation_and_captured_file_tools(tmp_path):
    path = os.environ.get('SIFTED_TEST_INVESTIGATION_IMAGE')
    if not path:
        pytest.skip('Set SIFTED_TEST_INVESTIGATION_IMAGE to the documented Citadel DC01 capture.')
    source = Path(path).resolve()
    with source.open('rb') as handle:
        baseline = hashlib.file_digest(handle, 'sha256').hexdigest()
    assert baseline == '8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62'
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path/'case.db'),
                      'SIFTED_INPUT_ROOTS': [str(source.parent), str(tmp_path)], 'SIFTED_OUTPUT_ROOTS': [str(tmp_path)],
                      'SIFTED_VOLATILITY_SYMBOLS': str(tmp_path/'symbols')})
    repo, client, settings = Repository(app.config['DATABASE_PATH']), app.test_client(), app.config['SETTINGS']
    installed = discover(settings)
    case, key = register(client, repo, source, 'memory_dump')
    worker = Worker(repo, settings)
    print('Case', case, 'source', key, flush=True)

    def run(action, options=None):
        data = {**action['payload'], **(options or {})}
        assert not action.get('reason'), action
        response = client.post(f'/api/{action["tool"]}/run', json=data)
        assert response.status_code == 202, response.json
        worker.run_once()
        result = repo.run(response.json['run_id'])
        print(action['label'], result['status'], result.get('error'), flush=True)
        assert result['status'] == 'success', result.get('error')
        return result

    memory = view(client, case, key)['memory']
    run(memory['identify'])
    inventory = run(memory['inventory_action'])
    report = inventory['plugin_results'][0]['file']
    rows = published.page(inventory, report, repo, settings, limit=10000)['rows']
    chosen = next(row for row in rows if row['values']['ImageFileName'].lower() == 'explorer.exe')
    pid = chosen['values']['PID']
    assert len(rows) > 20
    actions = view(client, case, key, tab='processes', process_row=chosen['id'])['memory']['process_actions']
    for action in actions:
        payload = json.loads(json.dumps(action['payload']))
        if action['fields']:
            rules = tmp_path/'reviewed rules.yar'
            rules.write_text('rule pe_dos_message { strings: $a="This program cannot be run in DOS mode" condition: $a }')
            payload['plugin_options'][action['plugin']]['yara_file'] = str(rules)
        result = run(action, payload)
        assert repo.input(result['id'])['process_selection']['pid'] == pid
        data = published.page(result, result['plugin_results'][0]['file'], repo, settings)
        assert all(row['values'].get('PID', pid) == pid for row in data['rows'])
        if action['id'] == 'rules':
            assert data['total'] > 0
            assert repo.input(result['id'])['related_files'][0]['path'] == str(rules)
        if action['id'] == 'extract':
            executable_run = result
    for question in ('network', 'injection', 'persistence', 'kernel'):
        model = view(client, case, key, tab='investigate', memory_question=question)['memory']
        for action in model['investigations']:
            if action['id'] == 'capture_hives':
                action = next(a for a in view(client, case, key, tab='investigate', memory_question=question)['memory']['investigations'] if a['id'] == 'capture_hives')
                hive = next(value for value, _ in action['fields'][0]['choices'] if value.endswith('\\SYSTEM'))
                action['payload']['plugin_options'][action['plugin']]['filter'] = hive
            result = run(action)
            if action['id'] == 'connection_scan':
                rows = published.page(result, result['plugin_results'][0]['file'], repo, settings, limit=10000)['rows']
                assert len(rows) > 0
                command = resolve_argv(result['plan']['steps'][0]['argv'], str(tmp_path/'direct'), str(tmp_path/'direct-job'))
                (tmp_path/'direct/plugins/windows.netscan.NetScan').mkdir(parents=True)
                direct = subprocess.run(command, capture_output=True, text=True, timeout=180)
                assert direct.returncode == 0, direct.stderr
                report = result['plugin_results'][0]['file']
                with published.artifact(result, report, repo, settings) as handle:
                    complete = [{k: v for k, v in row.items() if k != '__depth'} | {'__children': []}
                                for row in published.records(handle, report)]
                assert [json.loads(line) for line in direct.stdout.splitlines() if line.strip()] == complete
                response = client.get(f'/api/case/{case}/workspace/run/{result["id"]}', query_string={'input': key})
                assert response.status_code == 200 and 'Review PID' in response.json['html']
    # This acquisition has an unreadable user hive. A whole-list dump must not
    # publish its earlier/partial hive captures as complete evidence.
    response = client.post('/api/volatility/run', json={**model['identify']['payload'],
        'plugins': ['windows.registry.hivelist.HiveList'], 'plugin_options': {'windows.registry.hivelist.HiveList': {'dump': True}}})
    assert response.status_code == 202, response.json
    worker.run_once()
    failed = repo.run(response.json['run_id'])
    assert failed['status'] == 'error' and 'Page Fault' in failed['error']
    assert all(not a['complete'] for a in repo.artifacts(failed['id']))
    assert not any(item['source_run_id'] == failed['id'] for item in view(client, case, key)['derived'])
    # Every configured action is a real installed plugin, including the other OS profiles.
    for profile in PROFILES.values():
        for action in profile['process'] + profile['investigations']:
            assert action['plugin'] in installed['plugins']
    derived = view(client, case, key, tab='derived')['derived']
    captured = next(item for item in derived if item['source_run_id'] == executable_run['id'])
    assert Path(captured['path']).read_bytes().startswith(b'MZ')
    examination = view(client, case, key, tab='derived', examine=captured['key'])['examination']
    for tool in ('filetype', 'xxd', 'strings', 'clamscan'):
        action = next(a for a in examination['actions'] if a['id'] == tool)
        result = run(action)
        assert repo.input(result['id'])['source_run_id'] == executable_run['id']
    features = next(a for a in view(client, case, key, tab='investigate', memory_question='indicators')['memory']['investigations'] if a['id'] == 'features')
    result = run(features)
    assert (Path(result['output_path'])/'url.txt').is_file()
    # Exercise ClamAV's detection exit status with a private signature for the real
    # captured executable; this is test configuration, not fabricated evidence.
    data = Path(captured['path']).read_bytes()
    db = tmp_path/'known signatures'; db.mkdir()
    (db/'known.hdb').write_text(f'{hashlib.md5(data).hexdigest()}:{len(data)}:Sifted.Validation.CapturedProcess\n')
    settings.clamav_database = str(db)
    action = next(a for a in examination['actions'] if a['id'] == 'clamscan')
    matched = run(action)
    assert matched['steps'][-1]['return_code'] == 1 and matched['analysis']['signature_matches'] > 0
    assert 'Sifted.Validation.CapturedProcess' in (Path(matched['output_path'])/'detections.csv').read_text()
    with source.open('rb') as handle:
        assert hashlib.file_digest(handle, 'sha256').hexdigest() == baseline
