"""Real acquisitions retain their workflow through misleading names and uploads."""
import hashlib
import os
from pathlib import Path
import shutil

import pytest

from app import create_app
from sifted_core.storage import Repository
from sifted_core.worker import Worker
from test_evidence_workspace import view
from test_evidence_intake import assert_chain


@pytest.mark.live
@pytest.mark.parametrize('transport', ['workstation', 'renamed', 'upload'])
def test_native_memory_intake_selects_workflow_without_analyst_classification(tmp_path, transport):
    value = os.environ.get('SIFTED_TEST_INVESTIGATION_IMAGE')
    if not value:
        pytest.skip('Set SIFTED_TEST_INVESTIGATION_IMAGE to the documented Citadel DC01 capture.')
    source = Path(value).resolve()
    digest = '8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'case.db'),
                      'SIFTED_INPUT_ROOTS': [str(source.parent), str(tmp_path / 'inputs')],
                      'SIFTED_OUTPUT_ROOTS': [str(outputs)]})
    client, repo = app.test_client(), Repository(app.config['DATABASE_PATH'])
    client.post('/cases', data={'name': 'Native automatic profiling'})
    case = repo.cases()[0]['id']
    if transport == 'upload':
        response = client.post(f'/api/case/{case}/uploads', json={
            'files': [{'name': 'misleading.jpg', 'size': source.stat().st_size}], 'primary': 0,
            'metadata': {'custodian': 'Native profile validation', 'expected_sha256': digest}})
        assert response.status_code == 201, response.json
        base = f"/api/case/{case}/uploads/{response.json['id']}"
        offset = 0
        with source.open('rb') as handle:
            while chunk := handle.read(4 * 1024 ** 2):
                response = client.put(base + '/0', data=chunk, headers={'Upload-Offset': str(offset)})
                assert response.status_code == 200, response.json
                offset += len(chunk)
        response = client.post(base + '/complete')
    else:
        selected = source
        if transport == 'renamed':
            selected = tmp_path / 'inputs' / 'no-extension'
            selected.parent.mkdir()
            shutil.copyfile(source, selected)
        response = client.post(f'/api/case/{case}/artifacts', json={
            'path': str(selected), 'custodian': 'Native profile validation', 'expected_sha256': digest})
    assert response.status_code == 202, response.json
    Worker(repo, app.config['SETTINGS']).run_once()
    run = repo.run(response.json['run_id'])
    assert run['status'] == 'success', run.get('error')
    item = repo.case(case)['artifacts'][0]
    assert item['hash'] == digest and item['type_basis'] == 'content' and item['type'] == 'memory_dump'
    observed = item['profile']
    assert observed['kind'] == 'memory' and observed['assessment']['status'] == 'supported'
    assert observed['memory']['os'] == 'windows' and observed['memory']['nt_major'] == 6
    assert observed['memory']['nt_minor'] == 3
    assert observed['memory']['system_root'] == 'C:\\Windows'
    assert any(p['name'] == 'memory' and p['status'] == 'matched' for p in observed['assessment']['probes'])
    model = view(client, case, 'e:' + item['id'])
    assert model['is_memory'] and not model['acquisition']['needed']
    assert model['memory']['os'] == 'windows'
    assert_chain(repo.custody(case, item['id']))
    assert not any(e['event'] == 'classification_changed' for e in repo.custody(case, item['id'])['events'])
    with source.open('rb') as handle:
        assert hashlib.file_digest(handle, 'sha256').hexdigest() == digest
