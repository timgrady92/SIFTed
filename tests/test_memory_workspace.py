"""Memory selections stay tied to verified runs, rows, process options and bytes."""
import copy
from pathlib import Path

import pytest

from app import create_app
from sifted_core.memory_analysis import PROFILES
from sifted_core.worker import Worker
from test_evidence_workspace import register, view
from test_volatility import memory_runtime as memory_runtime, option


@pytest.fixture
def memory_workspace(memory_runtime):
    repo, settings, source, installed = memory_runtime
    source.write_bytes(b'\0' * 4096)
    for profile in PROFILES.values():
        for plugin in [profile['identify'], profile['inventory'], *(x[1] for x in profile['checks'])]:
            installed['plugins'][plugin] = {'os': plugin.split('.')[0], 'description': plugin, 'options': []}
        for spec in profile['process'] + profile['investigations']:
            plugin = spec['plugin']
            entry = installed['plugins'].setdefault(plugin, {'os': plugin.split('.')[0], 'description': plugin, 'options': []})
            options = {o['name']: o for o in entry['options']}
            if spec['pid']:
                options[spec['pid']] = option(spec['pid'], 'integer' if plugin == 'windows.memmap.Memmap' else 'integer_list')
            options.update({k: option(k, 'boolean') for k in spec['options']})
            options.update({field['name']: option(field['name'], field['native_type']) for field in spec['fields']})
            entry['options'] = list(options.values())
    Path(installed['argv_prefix'][1]).write_text('''import json,sys
from pathlib import Path
a=sys.argv[1:]; out=Path(a[a.index('-o')+1]); plugin=a[a.index('-o')+2]
Path(a[a.index('--save-config')+1]).write_text(json.dumps({'plugin':plugin}))
pids=[int(a[a.index('--pid')+1])] if '--pid' in a else [int(a[a.index('--pids')+1])] if '--pids' in a else range(120)
rows=[{'PID':pid,'PPID':0,'ImageFileName':f'process-{pid}.exe','Offset(V)':18446735277616529408+pid,'__children':[]} for pid in pids]
if plugin.endswith('.Info') or plugin=='banners.Banners': rows=[{'Variable':'Kernel','Value':'test context'},{'Variable':'NtMajorVersion','Value':'10'}]
if plugin.endswith('.HiveList'): rows=[{'Offset':18446735277616529408,'FileFullPath':'SYSTEM'}]
if '--dump' in a: (out/'process.dmp').write_bytes(b'MZ'+b'\\0'*128)
if a[a.index('-r')+1]=='json': print(json.dumps(rows))
else:
 for row in rows: print(json.dumps(row))
''')
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(repo.path),
                      'SIFTED_INPUT_ROOTS': settings.input_roots, 'SIFTED_OUTPUT_ROOTS': settings.output_roots,
                      'SIFTED_VOLATILITY_SYMBOLS': settings.volatility_symbols})
    client = app.test_client()
    case, key = register(client, repo, source, 'memory_dump')
    return app, client, repo, settings, source, case, key, installed


def execute(runtime, payload):
    _, client, repo, settings, *_ = runtime
    response = client.post('/api/volatility/run', json=payload)
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    result = repo.run(response.json['run_id'])
    assert result['status'] == 'success', result.get('error')
    return result


def inventory(runtime, os='windows', **options):
    _, client, _, _, _, case, key, _ = runtime
    model = view(client, case, key, memory_os=os)
    return execute(runtime, {**model['memory']['inventory_action']['payload'], **options})


def selected(runtime, run, row=43, **options):
    _, client, _, _, _, case, key, _ = runtime
    return view(client, case, key, tab='processes', inventory_run_id=run['id'], process_row=row, **options)


@pytest.mark.parametrize('os', PROFILES)
def test_process_inventory_paging_filter_and_scoped_extraction(memory_workspace, os):
    runtime = memory_workspace
    _, client, repo, _, _, case, key, _ = runtime
    model = view(client, case, key, memory_os=os)
    assert model['is_memory'] and not model['is_disk']
    assert [t[0] for t in model['tabs']] == ['overview', 'analysis', 'processes', 'investigate', 'derived', 'activity']
    execute(runtime, model['memory']['identify']['payload'])
    run = inventory(runtime, os)
    model = selected(runtime, run, memory_os=os)
    table = model['memory']['processes']
    assert table['total'] == 120 and len(table['rows']) == 50 and table['more']
    assert table['selected']['values']['PID'] == 42
    page = view(client, case, key, tab='processes', memory_os=os, process_offset=100)['memory']['processes']
    assert len(page['rows']) == 20 and not page['more']
    found = view(client, case, key, tab='processes', memory_os=os, process_q='process-42.exe')['memory']['processes']
    assert found['total'] == 1 and found['rows'][0]['id'] == 43
    for action in (a for a in model['memory']['process_actions'] if a['group'] == 'essential'):
        result = execute(runtime, action['payload'])
        selection = repo.input(result['id'])['process_selection']
        assert selection['pid'] == 42 and selection['run_id'] == run['id'] and selection['row_id'] == 43
        assert selection['record']['Offset(V)'] == 18446735277616529450
        refreshed = selected(runtime, run, memory_os=os)
        assert any(a['run_id'] == result['id'] for a in refreshed['memory']['process_actions'])
        response = client.get(f'/api/case/{case}/workspace/run/{result["id"]}', query_string={'input': key})
        assert response.status_code == 200 and 'workspace-result-table' in response.json['html']
    if os != 'mac':
        derived = view(client, case, key, tab='derived')['derived']
        assert len(derived) == 1 and Path(derived[0]['path']).read_bytes().startswith(b'MZ')
        assert all('result.json' not in d['path'] for d in derived)
    assert client.get(f'/case/{case}/workspace', query_string={'input': key, 'tab': 'processes', 'memory_os': os, 'process_row': 43}).status_code == 200


@pytest.mark.parametrize('renderer', ['json', 'jsonl'])
def test_standalone_inventory_is_reused_and_nested_results_are_available(memory_workspace, renderer):
    runtime = memory_workspace
    _, client, _, _, source, case, key, _ = runtime
    # No workspace-specific metadata is needed to participate in the journey.
    result = execute(runtime, {'case_id': case, 'source_path': str(source), 'plugins': ['windows.pslist.PsList'], 'renderer': renderer})
    model = view(client, case, key, tab='processes')
    assert model['memory']['inventory']['id'] == result['id']
    response = client.get(f'/api/case/{case}/workspace/run/{result["id"]}', query_string={'input': key, 'report_offset': 100})
    assert 'Showing 101–120' in response.json['html']
    assert '18446735277616529508' in response.json['html']


def test_filtered_results_and_failed_runs_cannot_become_full_inventories(memory_workspace):
    runtime = memory_workspace
    _, client, repo, settings, _, case, key, _ = runtime
    inventory(runtime, plugin_options={'windows.pslist.PsList': {'pid': [42]}})
    assert view(client, case, key)['memory']['inventory'] is None
    run = inventory(runtime)
    model = selected(runtime, run)
    action = model['memory']['process_actions'][0]['payload']
    # Changing a published report invalidates both viewing and submission.
    report = Path(run['output_path']) / run['plugin_results'][0]['file']
    original = report.read_bytes()
    report.write_bytes(original + b'\n')
    assert 'changed' in selected(runtime, run)['memory']['error']
    assert client.post('/api/volatility/run', json=action).status_code == 400
    report.write_bytes(original)
    queued = client.post('/api/volatility/run', json=action)
    assert queued.status_code == 202
    report.write_bytes(b'{}\n')
    Worker(repo, settings).run_once()
    failed = repo.run(queued.json['run_id'])
    assert failed['status'] == 'error' and 'changed' in failed['error']


@pytest.mark.parametrize('change', ['pid', 'plugin', 'row', 'case', 'null', 'missing', 'source'])
def test_process_selection_rejects_forged_context(memory_workspace, change):
    runtime = memory_workspace
    _, client, repo, _, source, case, key, _ = runtime
    run = inventory(runtime)
    payload = copy.deepcopy(selected(runtime, run)['memory']['process_actions'][0]['payload'])
    plugin = payload['plugins'][0]
    if change == 'pid': payload['plugin_options'][plugin]['pid'] = [99]
    elif change == 'plugin': payload['process_ref']['plugin'] = 'windows.cmdline.CmdLine'
    elif change == 'row': payload['process_ref']['row_id'] = 999
    elif change == 'null': payload['process_ref'] = None
    elif change == 'missing': payload['process_ref']['run_id'] = 'missing'
    elif change == 'source':
        other = source.parent / 'another.raw'; other.write_bytes(source.read_bytes())
        payload.update(source_path=str(other)); payload.pop('workspace_input')
    else:
        client.post('/cases', data={'name': 'Different case'})
        payload['case_id'] = next(c['id'] for c in repo.cases() if c['id'] != case)
        payload.pop('workspace_input')
    before = len(repo.runs())
    response = client.post('/api/volatility/run', json=payload)
    assert response.status_code == 400, response.json
    assert len(repo.runs()) == before


def test_absent_plugin_and_other_os_results_do_not_offer_misleading_actions(memory_workspace):
    runtime = memory_workspace
    _, client, _, _, _, case, key, installed = runtime
    run = inventory(runtime)
    installed['plugins']['windows.cmdline.CmdLine']['options'][0]['type'] = 'string'
    assert 'process selector' in selected(runtime, run)['memory']['process_actions'][0]['reason']
    del installed['plugins']['windows.cmdline.CmdLine']
    assert 'unavailable' in selected(runtime, run)['memory']['process_actions'][0]['reason']
    assert view(client, case, key, memory_os='linux')['memory']['inventory'] is None
    assert client.get(f'/api/case/{case}/workspace', query_string={'input': key, 'memory_os': 'invalid'}).status_code == 400
    assert client.get(f'/api/case/{case}/workspace', query_string={'input': key, 'inventory_run_id': run['id'], 'memory_os': 'linux'}).status_code == 400


@pytest.mark.parametrize('os', PROFILES)
def test_every_guided_process_contract_and_rules_provenance(memory_workspace, os):
    runtime = memory_workspace
    _, client, repo, settings, source, case, key, _ = runtime
    run = inventory(runtime, os)
    rules = source.parent / 'reviewed rules.yar'
    rules.write_text('rule known_marker { strings: $a="process" condition: $a }')
    actions = selected(runtime, run, memory_os=os)['memory']['process_actions']
    for action in actions:
        assert not action['reason'], action
        payload = copy.deepcopy(action['payload'])
        for field in action['fields']:
            assert client.post('/api/volatility/preview', json=payload).status_code == 400
            payload['plugin_options'][action['plugin']][field['name']] = str(rules)
        result = execute(runtime, payload)
        assert repo.input(result['id'])['process_selection']['pid'] == 42
        if action['fields']:
            record = repo.input(result['id'])
            assert record['related_files'][0]['path'] == str(rules)
        if action['plugin'] == 'windows.memmap.Memmap':
            assert payload['plugin_options'][action['plugin']]['pid'] == 42  # scalar, unlike pslist
    # A new plugin option cannot be smuggled into a selected-process request.
    action = copy.deepcopy(actions[0]['payload'])
    action['plugin_options'][action['plugins'][0]]['dump'] = True
    assert client.post('/api/volatility/run', json=action).status_code == 400


def test_network_context_gating_report_search_and_pid_pivots(memory_workspace):
    runtime = memory_workspace
    _, client, repo, _, _, case, key, _ = runtime
    run = inventory(runtime)
    model = view(client, case, key, tab='investigate')['memory']
    assert all('Identify the Windows version' in action['reason'] for action in model['investigations'])
    # A signed real output contract, not a filename, determines Windows support.
    info = execute(runtime, model['identify']['payload'])
    assert all(not action['reason'] for action in view(client, case, key, tab='investigate')['memory']['investigations'])
    result = execute(runtime, selected(runtime, run)['memory']['process_actions'][0]['payload'])
    response = client.get(f'/api/case/{case}/workspace/run/{result["id"]}', query_string={'input': key, 'report_q': 'process-42'})
    assert response.status_code == 200 and 'Review PID 42' in response.json['html']
    assert 'process_row=43' in response.json['html']
    assert '0 rows' in client.get(f'/api/case/{case}/workspace/run/{result["id"]}', query_string={'input': key, 'report_q': 'not-present'}).json['html']
    path = Path(info['output_path']) / info['plugin_results'][0]['file']
    path.write_text('{"Variable":"NtMajorVersion","Value":"10"}\n')
    assert all(action['reason'] for action in view(client, case, key, tab='investigate')['memory']['investigations'])


@pytest.mark.parametrize('context', ['duplicate_pid', 'different_os'])
def test_report_does_not_link_ambiguous_or_different_os_processes(memory_workspace, context):
    _, client, repo, settings, _, case, key, installed = memory_workspace
    if context == 'duplicate_pid':
        script = Path(installed['argv_prefix'][1])
        script.write_text(script.read_text().replace('range(120)', '[42, 42]'))
    inventory(memory_workspace)
    action = view(client, case, key, tab='investigate', memory_question='injection')['memory']['investigations'][0]
    result = execute(memory_workspace, action['payload'])
    if context == 'different_os':
        inventory(memory_workspace, os='linux')
    response = client.get(f'/api/case/{case}/workspace/run/{result["id"]}', query_string={
        'input': key, 'memory_os': 'linux' if context == 'different_os' else 'windows'})
    assert response.status_code == 200 and 'Review PID' not in response.json['html']


def test_hive_extraction_uses_verified_listing_choices(memory_workspace):
    _, client, repo, settings, _, case, key, _ = memory_workspace

    def actions():
        return {a['id']: a for a in view(client, case, key, tab='investigate', memory_question='persistence')['memory']['investigations']}

    assert 'Locate registry hives first' in actions()['capture_hives']['reason']
    listing = execute(memory_workspace, actions()['hives']['payload'])
    action = actions()['capture_hives']
    assert not action['reason'] and ['SYSTEM', 'SYSTEM'] in action['fields'][0]['choices']
    payload = copy.deepcopy(action['payload'])
    payload['plugin_options'][action['plugin']]['filter'] = 'SYSTEM'
    result = execute(memory_workspace, payload)
    assert actions()['capture_hives']['run_id'] == result['id']
    report = Path(listing['output_path']) / listing['plugin_results'][0]['file']
    report.write_text('[]')
    assert 'could not be verified' in actions()['capture_hives']['reason']


@pytest.mark.parametrize('os', PROFILES)
def test_investigation_questions_use_catalog_and_shared_adapters(memory_workspace, os):
    _, client, repo, settings, source, case, key, installed = memory_workspace
    from sifted_core.adapters import compile_plan
    from sifted_core.memory_catalog import QUESTIONS
    for question in QUESTIONS:
        model = view(client, case, key, tab='investigate', memory_os=os, memory_question=question)['memory']
        for action in model['investigations']:
            if action['tool'] != 'volatility' or action['reason']:
                continue
            payload = copy.deepcopy(action['payload'])
            for field in action['fields']:
                rules = source.parent / 'known.yar'; rules.write_text('rule known { condition: true }')
                payload['plugin_options'][action['plugin']][field['name']] = str(rules)
            plan, _, _ = compile_plan(action['tool'], payload, settings, repo)
            assert plan.tool == 'volatility' and plan.postprocess == 'volatility'
    assert client.get(f'/case/{case}/workspace', query_string={'input': key, 'tab': 'investigate', 'memory_os': os}).status_code == 200
