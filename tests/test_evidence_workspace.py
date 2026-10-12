"""Artifact suitability, isolated selection, result reuse and guided execution."""
from pathlib import Path

import pytest

from app import create_app
from sifted_core.context import runtime_repository
from sifted_core.evidence_workspace import identify, select_input
from sifted_core.worker import Worker
from test_integrated_tools import integrated as integrated
from test_zimmerman import zimmerman_runtime as zimmerman_runtime, input_for


def register(client, repo, path, kind=None):
    client.post('/cases', data={'name': 'Workspace case'})
    case = repo.cases()[-1]
    response = client.post(f"/api/case/{case['id']}/artifacts", json={'path': str(path), **({'type': kind} if kind else {})})
    assert response.status_code == 202, response.json
    while repo.run(response.json['run_id'])['status'] == 'queued':
        Worker(repo, client.application.config['SETTINGS']).run_once()
    assert repo.run(response.json['run_id'])['status'] == 'success', repo.run(response.json['run_id']).get('error')
    return case['id'], 'e:' + response.json['artifact']['id']


def view(client, case, key, **args):
    response = client.get(f'/api/case/{case}/workspace', query_string={'input': key, **args})
    assert response.status_code == 200, response.json
    return response.json


def payload(action):
    return dict(action['payload'])


@pytest.fixture
def workspace_runtime(integrated):
    app, repo, settings, source, outputs = integrated
    header = bytearray(512)
    header[450] = 0x83
    header[454:458] = (2048).to_bytes(4, 'little')
    header[458:462] = (2048).to_bytes(4, 'little')
    header[510:512] = b'\x55\xaa'
    source.write_bytes(header)
    client = app.test_client()
    case, key = register(client, repo, source, 'disk_image')
    return app, client, repo, settings, source, outputs, case, key


def test_workspace_is_optional_and_empty_cases_are_usable(tmp_path):
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path/'db'), 'SIFTED_INPUT_ROOTS': [str(tmp_path)], 'SIFTED_OUTPUT_ROOTS': [str(tmp_path)]})
    client = app.test_client()
    assert b'Create a case' in client.get('/evidence').data
    client.post('/cases', data={'name': 'Empty'})
    with app.app_context():
        case = runtime_repository().cases()[0]
    assert b'No evidence yet' in client.get(f"/case/{case['id']}/workspace").data
    for route in ('/', '/tools', '/cases', '/disk-analysis', '/file-examination', '/strings', '/workflow/mmls'):
        assert client.get(route).status_code == 200
    assert client.get('/case/missing/workspace').status_code == 404


def test_raw_is_ambiguous_until_analyst_classifies_it(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    raw = source.parent/'memory.raw'
    raw.write_bytes(b'\0' * 1024)
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(raw)})
    assert response.status_code == 202
    Worker(repo, settings).run_once()
    item = repo.case(case)['artifacts'][-1]
    key = 'e:' + item['id']
    initial = view(client, case, key)
    assert initial['observed']['kind'] == 'unknown'
    assert 'volatility' not in {a['id'] for a in initial['actions']}
    assert client.post(f"/case/{case}/evidence/{item['id']}/type", data={'type': 'memory_dump'}).status_code == 302
    memory = view(client, case, key)
    assert memory['observed']['kind'] == 'memory' and memory['observed']['basis'] == 'Analyst selection'
    assert any(a['id'] == 'volatility' and a['recommended'] for a in memory['actions'])
    assert repo.case(case)['artifacts'][-1]['hash'] == item['hash']


def test_content_overrides_misleading_extension_and_declared_type(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    misleading = source.parent / 'photo.E01'
    misleading.write_bytes(b'%PDF-1.7\nknown document')
    case, key = register(client, repo, misleading, 'disk_image')
    result = view(client, case, key)
    assert result['observed']['kind'] == 'pdf'
    ids = {a['id'] for a in result['actions']}
    assert {'pdfinfo', 'pdftotext'} <= ids and 'mmls' not in ids
    assert 'differs' in result['observed']['note']
    misleading.write_bytes(b'replaced evidence')
    assert not view(client, case, key)['observed']['available']
    overview = client.get(f'/case/{case}/workspace', query_string={'input': key, 'tab': 'overview'})
    assert b'Reverify' in overview.data and b'Continue to Analysis' not in overview.data


def test_disabled_missing_tools_and_missing_evidence(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    settings.binaries['mmls'] = ['/missing/mmls']
    data = view(client, case, key)
    action = next(a for a in data['actions'] if a['id'] == 'mmls')
    assert not action['enabled'] and 'unavailable' in action['reason']
    source.unlink()
    data = view(client, case, key)
    assert not data['observed']['available'] and not any(a['enabled'] for a in data['actions'])


def test_workspace_selection_and_submission_cannot_cross_cases(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    other, other_key = register(client, repo, source)
    assert client.get(f'/api/case/{other}/workspace', query_string={'input': key}).status_code == 400
    data = {'case_id': other, 'source_path': str(source), 'workspace_input': key}
    assert client.post('/api/xxd/run', json=data).status_code == 400
    data['case_id'] = case
    data['source_path'] = str(source.parent/'different.bin')
    assert client.post('/api/xxd/run', json=data).status_code == 400
    assert all(run['tool'] == 'evidence-intake' for run in repo.runs())


def test_guided_partition_inventory_extraction_and_result_reuse(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    initial = view(client, case, key)
    action = next(a for a in initial['actions'] if a['id'] == 'mmls')
    data = payload(action)
    created = client.post('/api/mmls/run', json=data)
    assert created.status_code == 202, created.json
    worker = Worker(repo, settings)
    worker.run_once()
    mapped = view(client, case, key)
    assert len(mapped['partitions']) == 1
    assert mapped['partitions'][0]['offset_sector'] == 2048
    action = next(a for a in mapped['actions'] if a['id'] == 'mmls')
    assert action['result_run_id'] == created.json['run_id']
    assert client.get(f'/api/case/{case}/workspace/run/{action["result_run_id"]}', query_string={'input': key}).status_code == 200
    inventory = mapped['journey'][0]['inventory_payload']
    preview = client.post('/api/fls/preview', json=inventory)
    assert preview.status_code == 200 and '-o 2048' in preview.json['terminal_command']
    forged = {**inventory, 'offset_sector': 4096}
    assert client.post('/api/fls/run', json=forged).status_code == 400
    response = client.post('/api/fls/run', json=inventory)
    assert response.status_code == 202, response.json
    worker.run_once()
    context = response.json['run_id']
    selected = view(client, case, key, context_run_id=context)
    assert selected['journey'][0]['offset_sector'] == 2048
    fls = next(a for a in selected['actions'] if a['id'] == 'fls')
    assert fls['result_run_id'] == context
    assert payload(fls)['context_run_id'] == context
    triage = view(client, case, key, tab='triage', context_run_id=context)
    selected_file = next(row for row in triage['triage']['rows'] if row['address'] == '42-128-1')
    extract = selected_file['extract_payload']
    assert extract['recover_deleted'] and extract['entry_id'] == selected_file['id']
    response = client.post('/api/icat/run', json=extract)
    assert response.status_code == 202, response.json
    worker.run_once()
    data = view(client, case, key)
    derived = [x for x in data['inputs'] if x['origin'] == 'derived']
    assert len(derived) == 1 and derived[0]['artifact_kind'] == 'extracted_file'
    new_key = derived[0]['key']
    data = view(client, case, key, tab='derived', examine=new_key)
    assert data['selected']['key'] == key
    xxd = next(a for a in data['examination']['actions'] if a['id'] == 'xxd')
    response = client.post('/api/xxd/run', json=payload(xxd))
    assert response.status_code == 202, response.json
    worker.run_once()
    assert repo.input(response.json['run_id'])['source_run_id'] == derived[0]['source_run_id']
    assert len(repo.runs()) == 5
    assert all(r['status'] == 'success' for r in repo.runs())
    assert not any(x['label'].endswith('.csv') for x in derived)


def test_tampered_partition_map_cannot_guide_execution(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    created = client.post('/api/mmls/run', json={'case_id': case, 'source_path': str(source), 'workspace_input': key})
    Worker(repo, settings).run_once()
    mapped = view(client, case, key)
    data = mapped['journey'][0]['inventory_payload']
    run = repo.run(created.json['run_id'])
    (Path(run['output_path'])/'mmls.csv').write_text('tampered')
    assert not view(client, case, key)['partitions']
    assert client.post('/api/fls/run', json=data).status_code == 400


def test_block_samples_remain_blocks_even_with_document_headers(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    created = client.post('/api/blkcat/run', json={'case_id': case, 'source_path': str(source), 'block_address': 1})
    Worker(repo, settings).run_once()
    data = view(client, case, key)
    block = next(x for x in data['inputs'] if x['origin'] == 'derived')
    assert block['artifact_kind'] == 'filesystem_block_sample'
    result = view(client, case, block['key'])
    assert result['observed']['kind'] == 'block'
    assert {a['id'] for a in result['actions']} == {'filetype', 'xxd', 'strings'}
    (Path(block['path'])).write_bytes(b'%PDF-1.7\n')
    result = view(client, case, block['key'])
    assert result['observed']['kind'] == 'block'
    xxd = next(a for a in result['actions'] if a['id'] == 'xxd')
    created = client.post('/api/xxd/run', json=payload(xxd))
    Worker(repo, settings).run_once()
    assert repo.run(created.json['run_id'])['status'] == 'error'


def test_completed_basic_examinations_reopen_without_reexecuting(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    action = next(a for a in view(client, case, key)['actions'] if a['id'] == 'xxd')
    created = client.post('/api/xxd/run', json=payload(action))
    Worker(repo, settings).run_once()
    action = next(a for a in view(client, case, key)['actions'] if a['id'] == 'xxd')
    assert action['result_run_id'] == created.json['run_id']
    page = client.get(f'/api/case/{case}/workspace/run/{action["result_run_id"]}', query_string={'input': key})
    assert page.status_code == 200 and 'xxd.txt' in page.json['html'] and '00000000' in page.json['html']
    assert len(repo.runs()) == 2


def test_outside_input_is_never_opened(workspace_runtime, monkeypatch):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    item = select_input(repo.case(case), repo, key)
    settings.input_roots = [str(outputs)]
    monkeypatch.setattr(Path, 'open', lambda *a, **k: pytest.fail('Opened disallowed evidence'))
    observed = identify(item, settings)
    assert not observed['available'] and 'outside' in observed['note']


@pytest.mark.parametrize('parser', ['amcacheparser', 'appcompatcacheparser', 'lecmd', 'jlecmd', 'rbcmd', 'recentfilecacheparser', 'evtxecmd', 'mftecmd', 'recmd', 'sqlecmd', 'sbecmd'])
def test_all_zimmerman_families_are_contextually_accessible(zimmerman_runtime, parser):
    repo, settings, evidence, outputs, native = zimmerman_runtime
    source = input_for(zimmerman_runtime, parser)
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(repo.path), 'SIFTED_INPUT_ROOTS': settings.input_roots,
                      'SIFTED_OUTPUT_ROOTS': settings.output_roots, 'SIFTED_EZ_ROOT': settings.ez_root, 'SIFTED_BINARIES': settings.binaries})
    client = app.test_client()
    case, key = register(client, repo, source)
    result = view(client, case, key)
    assert parser in {a['id'] for a in result['actions']}, result['observed']
    action = next(a for a in result['actions'] if a['id'] == parser)
    assert action['enabled'], action['reason']
    assert action['payload']['tool_id'] == parser
    data = payload(action)
    data['tool_id'] = parser
    response = client.post('/api/eric-zimmerman/run', json=data)
    assert response.status_code == 202, response.json
    Worker(repo, app.config['SETTINGS']).run_once()
    assert repo.run(response.json['run_id'])['status'] == 'success'
    updated = view(client, case, key)
    assert next(a for a in updated['actions'] if a['id'] == parser)['result_run_id'] == response.json['run_id']


def test_html_escapes_artifact_labels(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    repo.mutate_case(case, lambda value: value['artifacts'][0].update(label='<script>alert(1)</script>'))
    result = client.get(f'/case/{case}/workspace', query_string={'input': key})
    assert result.status_code == 200
    assert b'<script>alert(1)</script>' not in result.data and b'&lt;script&gt;' in result.data


from test_carving import carving_runtime as carving_runtime
from test_volatility import memory_runtime as memory_runtime


@pytest.mark.parametrize('tool', ['foremost', 'scalpel'])
def test_workspace_carved_inputs_exclude_audits_and_supporting_reports(carving_runtime, tool):
    repo, settings, source, native = carving_runtime
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(repo.path), 'SIFTED_INPUT_ROOTS': settings.input_roots,
                      'SIFTED_OUTPUT_ROOTS': settings.output_roots, 'SIFTED_BINARIES': settings.binaries})
    client = app.test_client()
    case, key = register(client, repo, source, 'disk_image')
    created = client.post(f'/api/{tool}/run', json={'case_id': case, 'source_path': str(source), 'types': ['jpg']})
    assert created.status_code == 202, created.json
    Worker(repo, app.config['SETTINGS']).run_once()
    run = repo.run(created.json['run_id'])
    assert run['status'] == 'success'
    derived = [x for x in view(client, case, key)['inputs'] if x['origin'] == 'derived']
    assert len(derived) == 1 and derived[0]['label'] == 'jpg/00000000.jpg'
    assert derived[0]['artifact_kind'] == 'carved_file'


def test_workspace_volatility_inputs_exclude_saved_config_and_plugin_report(memory_runtime):
    repo, settings, source, installed = memory_runtime
    settings.binaries['volatility'] = installed['argv_prefix']
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(repo.path), 'SIFTED_INPUT_ROOTS': settings.input_roots,
                      'SIFTED_OUTPUT_ROOTS': settings.output_roots, 'SIFTED_BINARIES': settings.binaries})
    client = app.test_client()
    case, key = register(client, repo, source, 'memory_dump')
    created = client.post('/api/volatility/run', json={'case_id': case, 'source_path': str(source), 'plugins': ['windows.pslist.PsList'], 'plugin_options': {'windows.pslist.PsList': {'dump': True}}})
    assert created.status_code == 202, created.json
    Worker(repo, app.config['SETTINGS']).run_once()
    run = repo.run(created.json['run_id'])
    assert run['status'] == 'success'
    derived = [x for x in view(client, case, key)['inputs'] if x['origin'] == 'derived']
    assert len(derived) == 1 and derived[0]['label'].endswith('/same-name.bin')
    assert not any(x['label'].endswith(('result.json', 'config.json')) for x in derived)


def test_inline_reports_are_bounded_escaped_and_scoped_to_evidence(workspace_runtime):
    import sys
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    script = source.parent / 'report tool.py'
    script.write_text("print('<script>alert(1)</script>' + 'A' * 140000)")
    settings.binaries['xxd'] = [sys.executable, str(script)]
    created = client.post('/api/xxd/run', json=next(a['payload'] for a in view(client, case, key)['actions'] if a['id'] == 'xxd'))
    assert created.status_code == 202
    Worker(repo, settings).run_once()
    run_id = created.json['run_id']
    endpoint = f'/api/case/{case}/workspace/run/{run_id}'
    response = client.get(endpoint, query_string={'input': key})
    assert response.status_code == 200
    html = response.json['html']
    assert '&lt;script&gt;' in html and '<script>' not in html and 'first 128 KiB' in html
    assert len(html) < 140000
    assert str(source) in response.json['terminal_command']
    assert client.get(endpoint, query_string={'input': key, 'report': str(source)}).status_code == 400
    other = source.parent / 'unrelated.txt'
    other.write_text('unrelated evidence')
    registered = client.post(f'/api/case/{case}/artifacts', json={'path': str(other)}).json['artifact']
    assert client.get(endpoint, query_string={'input': 'e:' + registered['id']}).status_code == 400
    other_case, other_key = register(client, repo, other)
    assert client.get(f'/api/case/{other_case}/workspace/run/{run_id}', query_string={'input': other_key}).status_code == 400
    report = Path(repo.run(run_id)['output_path']) / 'xxd.txt'
    report.unlink()
    report.symlink_to(other)
    assert client.get(endpoint, query_string={'input': key}).status_code == 400


def test_inline_fragments_and_invalid_captured_file_do_not_enqueue(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    for tab in ('overview', 'analysis', 'triage', 'derived', 'activity'):
        response = client.get(f'/api/case/{case}/workspace/view', query_string={'input': key, 'tab': tab})
        assert response.status_code == 200 and response.json['html'] and response.json['active'] == []
    assert client.get(f'/api/case/{case}/workspace/view', query_string={'input': key, 'tab': 'derived', 'examine': 'd:999'}).status_code == 400
    assert all(run['tool'] == 'evidence-intake' for run in repo.runs())
