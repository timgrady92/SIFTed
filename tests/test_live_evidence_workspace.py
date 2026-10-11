"""Evidence-first disk journeys using installed forensic tools and known bytes."""
from pathlib import Path
import shutil

import pytest

from app import create_app
from sifted_core.storage import Repository
from sifted_core.worker import Worker
from test_evidence_workspace import register, view, payload
from tool_fixtures import make_disk, pdf_bytes


@pytest.mark.live
def test_native_workspace_real_ewf_case_evidence(tmp_path):
    import hashlib
    import os
    import subprocess
    from sifted_core.disk_tools import image_sources

    value = os.environ.get('SIFTED_TEST_DISK_IMAGE')
    if not value:
        pytest.skip('Set SIFTED_TEST_DISK_IMAGE to an available real disk acquisition.')
    source = Path(value).resolve()
    assert source.is_file()
    outputs = tmp_path/'isolated outputs'
    outputs.mkdir()
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path/'case.db'),
                      'SIFTED_INPUT_ROOTS': [str(source.parent)], 'SIFTED_OUTPUT_ROOTS': [str(outputs)]})
    repo, client = Repository(app.config['DATABASE_PATH']), app.test_client()
    case, key = register(client, repo, source, 'disk_image')
    baseline = repo.case(case)['artifacts'][0]['hash']
    worker = Worker(repo, app.config['SETTINGS'])

    def run(tool, data):
        response = client.post(f'/api/{tool}/run', json=data)
        assert response.status_code == 202, response.json
        worker.run_once()
        result = repo.run(response.json['run_id'])
        assert result['status'] == 'success', result.get('error')
        return result

    run('mmls', {'source_path': str(source), 'case_id': case, 'workspace_input': key})
    chosen = view(client, case, key)['partitions'][0]
    run('fsstat', payload(chosen['actions'][0]))
    card = view(client, case, key)['journey'][0]
    inventory = run('fls', payload({'url': card['inventory_url']}))
    triage = view(client, case, key, tab='triage', context_run_id=inventory['id'], scope='filesystem', kind='file', state='allocated')['triage']
    assert triage['total'] > 0
    entry = next(row for row in triage['rows'] if row.get('extract_url'))
    extracted = run('icat', payload({'url': entry['extract_url']}))
    material = next(item for item in view(client, case, key, tab='derived')['derived'] if item['source_run_id'] == extracted['id'])
    expected = subprocess.run(['icat', '-b', str(chosen['sector_size']), '-o', str(chosen['offset_sector']),
                               *image_sources(str(source)), entry['address']], check=True, capture_output=True).stdout
    assert Path(material['path']).read_bytes() == expected
    assert hashlib.sha256(source.read_bytes()).hexdigest() == baseline
    actions = view(client, case, material['key'])['actions']
    assert any(action['id'] == 'filetype' and action['enabled'] for action in actions)
    assert repo.input(extracted['id'])['filesystem_entry']['address'] == entry['address']


@pytest.mark.live
@pytest.mark.parametrize('sector_size', [512, 4096])
def test_native_workspace_partition_to_identified_pdf(tmp_path, sector_size):
    if not all(shutil.which(tool) for tool in ('mmls', 'fls', 'icat', 'pdfinfo', 'pdftotext')):
        pytest.skip('Sleuth Kit and Poppler are required for this native journey.')
    evidence = tmp_path/'evidence with spaces'
    evidence.mkdir()
    output = tmp_path/'outputs'
    output.mkdir()
    disk = make_disk(evidence, sector_size)
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path/'workspace.db'),
                      'SIFTED_INPUT_ROOTS': [str(evidence)], 'SIFTED_OUTPUT_ROOTS': [str(output)]})
    repo, client = Repository(app.config['DATABASE_PATH']), app.test_client()
    case, key = register(client, repo, disk['path'], 'disk_image')
    worker = Worker(repo, app.config['SETTINGS'])

    def run(tool, data):
        response = client.post(f'/api/{tool}/run', json=data)
        assert response.status_code == 202, response.json
        worker.run_once()
        result = repo.run(response.json['run_id'])
        assert result['status'] == 'success', result.get('error')
        return result

    assert view(client, case, key)['observed']['kind'] == 'disk'
    action = next(a for a in view(client, case, key)['actions'] if a['id'] == 'mmls')
    run('mmls', {**payload(action), 'sector_size': sector_size})
    partitions = view(client, case, key)['partitions']
    chosen = next(p for p in partitions if p['offset_sector'] == disk['offset'])
    assert chosen['sector_size'] == sector_size
    data = payload(chosen['actions'][1])
    inventory = run('fls', {**data, 'recursive': True})
    triage = view(client, case, key, tab='triage', context_run_id=inventory['id'])['triage']
    nested = next(row for row in triage['rows'] if row['name'] == 'nested')
    triage = view(client, case, key, tab='triage', context_run_id=inventory['id'], directory=nested['id'])['triage']
    document = next(row for row in triage['rows'] if row['name'] == 'known.pdf')
    extracted = run('icat', payload({'url': document['extract_url']}))
    material = next(x for x in view(client, case, key)['inputs'] if x.get('source_run_id') == extracted['id'])
    assert Path(material['path']).read_bytes() == pdf_bytes()
    result = view(client, case, material['key'])
    assert result['observed']['kind'] == 'pdf'
    action = next(a for a in result['actions'] if a['id'] == 'pdftotext')
    rendered = run('pdftotext', payload(action))
    assert 'Known forensic PDF marker' in (Path(rendered['output_path'])/'pdftotext.txt').read_text()
    assert repo.input(rendered['id'])['source_run_id'] == extracted['id']
    action = next(a for a in view(client, case, material['key'])['actions'] if a['id'] == 'pdftotext')
    assert action['result_run_id'] == rendered['id']
    assert client.get(action['result_url']).status_code == 200
    assert len(repo.runs()) == 4


from test_live_volatility import installed_memory as installed_memory, windows_sample as windows_sample


@pytest.mark.live
def test_native_workspace_memory_action_on_public_windows_image(installed_memory, windows_sample):
    import json
    repo, settings, synthetic, installed = installed_memory
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(repo.path),
                      'SIFTED_INPUT_ROOTS': settings.input_roots, 'SIFTED_OUTPUT_ROOTS': settings.output_roots,
                      'SIFTED_VOLATILITY_SYMBOLS': settings.volatility_symbols})
    client = app.test_client()
    case, key = register(client, repo, windows_sample, 'memory_dump')
    workspace = view(client, case, key)
    assert workspace['observed']['kind'] == 'memory'
    action = next(a for a in workspace['actions'] if a['id'] == 'volatility')
    assert action['enabled'] and action['recommended']
    response = client.post('/api/volatility/run', json={**payload(action), 'plugins': ['windows.pslist.PsList'], 'renderer': 'json'})
    assert response.status_code == 202, response.json
    Worker(repo, app.config['SETTINGS']).run_once()
    run = repo.run(response.json['run_id'])
    assert run['status'] == 'success', run.get('error')
    records = json.loads((Path(run['output_path'])/'plugins/windows.pslist.PsList/result.json').read_text())
    assert len(records) == 47 and any(row['PID'] == 1812 for row in records)
    result = view(client, case, key)
    assert next(a for a in result['actions'] if a['id'] == 'volatility')['result_run_id'] == run['id']
    assert len(result['inputs']) == 1  # Plugin reports and saved configs are not extracted evidence.
    assert client.get(next(a for a in result['actions'] if a['id'] == 'volatility')['result_url']).status_code == 200
