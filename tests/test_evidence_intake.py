"""End-to-end intake contracts: stable bytes, content profiles, transfer and custody."""
import hashlib
import sqlite3
from pathlib import Path

import pytest

from app import create_app
from sifted_core.context import runtime_repository
from sifted_core.evidence_profile import profile, interpretation
from sifted_core.integrity import canonical, hash_file, manifest_hash, ExecutionFailure
from sifted_core.worker import Worker
from zimmerman_samples import shortcut, custom_jump_list, recycle_bin, event_header


@pytest.fixture
def intake_runtime(tmp_path):
    inputs, outputs = tmp_path / 'inputs', tmp_path / 'outputs'
    inputs.mkdir()
    outputs.mkdir()
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'database'),
                      'SIFTED_INPUT_ROOTS': [str(inputs)], 'SIFTED_OUTPUT_ROOTS': [str(outputs)]})
    client = app.test_client()
    client.post('/cases', data={'name': 'Intake'})
    with app.app_context():
        repo = runtime_repository()
    case_id = repo.cases()[0]['id']
    return client, repo, app.config['SETTINGS'], case_id, inputs


def register(runtime, source, **options):
    client, repo, settings, case, _ = runtime
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(source), 'custodian': 'Examiner 1', **options})
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    artifact = next(x for x in repo.case(case)['artifacts'] if x['id'] == response.json['artifact']['id'])
    return artifact, repo.run(response.json['run_id'])


def upload(runtime, contents, primary=None, info=None):
    client, _, _, case, _ = runtime
    response = client.post(f'/api/case/{case}/uploads', json={
        'files': [{'name': name, 'size': len(data)} for name, data in contents],
        'primary': primary, 'metadata': info or {'custodian': 'Transfer examiner'}})
    assert response.status_code == 201, response.json
    return f"/api/case/{case}/uploads/{response.json['id']}"


def put(client, base, index, offset, data):
    return client.put(f'{base}/{index}', data=data, headers={'Upload-Offset': str(offset)})


def assert_chain(export):
    previous = None
    for event in export['events']:
        body = {k: v for k, v in event.items() if k != 'digest'}
        assert body['previous'] == previous
        assert hashlib.sha256(canonical(body)).hexdigest() == event['digest']
        previous = event['digest']
    assert export['head'] == previous
    assert export['event_count'] == len(export['events'])


def test_registration_is_queued_and_records_expected_hash_custody_and_content(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    source = root / 'misleading.raw'
    source.write_bytes(b'%PDF-1.7\nknown content\n')
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(source), 'expected_sha256': expected,
                           'custodian': 'Analyst', 'source': 'Acquisition A', 'notes': 'Received read-only'})
    item = response.json['artifact']
    assert response.status_code == 202 and item['status'] == 'pending' and item['hash'] == ''
    assert client.get(f'/api/case/{case}/inputs').json['inputs'] == []
    Worker(repo, settings).run_once()
    item = repo.case(case)['artifacts'][0]
    assert item['hash'] == expected and item['status'] == 'ready'
    assert item['profile']['kind'] == 'pdf' and item['type_basis'] == 'content'
    assert item['manifest'][0]['sha256'] == expected
    endpoint = f"/api/case/{case}/evidence/{item['id']}/custody"
    response = client.get(endpoint)
    assert response.headers['Content-Disposition'].startswith('attachment')
    audit = response.json['custody']
    assert_chain(audit)
    assert [e['event'] for e in audit['events']] == ['intake_requested', 'verification_queued', 'verification_succeeded', 'intake_completed']
    assert audit['events'][0]['details']['custodian'] == 'Analyst'
    with repo.connection() as db, pytest.raises(sqlite3.IntegrityError, match='append-only'):
        db.execute('DELETE FROM evidence_events')


def test_wrong_expected_hash_never_becomes_a_baseline_even_on_retry(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    source = root / 'bytes'
    source.write_bytes(b'actual bytes')
    item, run = register(intake_runtime, source, expected_sha256='0' * 64)
    assert run['status'] == 'error' and item['status'] == 'failed' and not item['hash']
    response = client.post(f"/api/case/{case}/evidence/{item['id']}/verify")
    assert response.status_code == 202
    Worker(repo, settings).run_once()
    assert repo.run(response.json['run_id'])['status'] == 'error'
    assert not repo.case(case)['artifacts'][0]['hash']


def test_directory_baseline_covers_nested_files_names_and_empty_directories(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    folder = root / 'collection'
    (folder / 'empty').mkdir(parents=True)
    (folder / 'nested').mkdir()
    source = folder / 'nested' / 'note'
    source.write_bytes(b'evidence')
    item, run = register(intake_runtime, folder)
    assert run['status'] == 'success'
    assert item['hash'] == manifest_hash(item['manifest'])
    assert {'path': 'empty', 'kind': 'directory'} in item['manifest']
    source.write_bytes(b'changed!')
    response = client.post('/api/filetype/run', json={'case_id': case, 'source_path': str(folder)})
    assert response.status_code == 202
    Worker(repo, settings).run_once()
    failed = repo.run(response.json['run_id'])
    assert failed['status'] == 'error' and 'manifest' in failed['error']
    assert not failed['steps']
    assert repo.case(case)['artifacts'][0]['hash'] == item['hash']


def test_segment_hashes_apply_to_every_tool_and_membership_is_verified(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    first = root / 'acquisition.E01'
    first.write_bytes(b'EVF\x09\x0d\x0a\xff\x00' + b'\0' * 512)
    second = root / 'acquisition.E02'
    second.write_bytes(b'EVF\x09\x0d\x0a\xff\x00' + b'\2' * 512)
    item, run = register(intake_runtime, first)
    assert run['status'] == 'success' and item['profile']['kind'] == 'ewf'
    assert len(item['manifest']) == 2
    second.write_bytes(b'changed')
    response = client.post('/api/strings/run', json={'case_id': case, 'source_path': str(first)})
    Worker(repo, settings).run_once()
    failed = repo.run(response.json['run_id'])
    assert failed['status'] == 'error' and not failed['steps']
    assert 'manifest baseline' in failed['error']


def test_sources_cannot_change_or_use_symlinks_during_intake(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    source = root / 'source'
    source.write_bytes(b'before')
    linked = root / 'linked'
    linked.symlink_to(source)
    assert client.post(f'/api/case/{case}/artifacts', json={'path': str(linked)}).status_code == 400
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(source)})
    source.write_bytes(b'after')
    Worker(repo, settings).run_once()
    assert repo.run(response.json['run_id'])['status'] == 'error'
    assert not repo.case(case)['artifacts'][0]['hash']
    with pytest.raises(ExecutionFailure, match='changed'):
        hash_file(source, lambda: source.write_bytes(b'other'))


def test_standalone_case_entry_uses_the_same_intake_and_retirement_preserves_history(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    source = root / 'note'
    source.write_bytes(b'Independent examination\n')
    response = client.post('/api/strings/run', json={'case_id': case, 'source_path': str(source)})
    assert response.status_code == 202
    item = repo.case(case)['artifacts'][0]
    assert item['status'] == 'pending'
    assert client.delete(f"/api/case/{case}/artifacts/{item['id']}").status_code == 400
    Worker(repo, settings).run_once()
    item = repo.case(case)['artifacts'][0]
    assert item['status'] == 'ready' and item['profile']['kind'] == 'text'
    assert client.delete(f"/api/case/{case}/artifacts/{item['id']}").status_code == 200
    assert source.exists()
    assert repo.case(case)['artifacts'][0]['status'] == 'retired'
    assert client.get(f'/api/case/{case}/inputs').json['inputs'] == []
    assert client.post('/api/strings/run', json={'case_id': case, 'source_path': str(source)}).status_code == 400
    assert_chain(repo.custody(case, item['id']))
    assert repo.custody(case, item['id'])['events'][-1]['event'] == 'retired'


@pytest.mark.parametrize('name', ['image.E01', 'SYSTEM', 'memory.raw', 'records.evtx', 'anything'])
def test_misleading_filenames_never_establish_format(intake_runtime, name):
    *_, settings, case, root = intake_runtime
    path = root / name
    path.write_bytes(b'\0' * 4096)
    detected = profile(path, settings)
    assert detected['kind'] == 'unknown'


@pytest.mark.parametrize(('data', 'kind'), [(shortcut(), 'shortcut'), (custom_jump_list(), 'jump_list'),
                         (recycle_bin(), 'recycle_bin'), (event_header(), 'evtx')])
def test_forensic_profiles_survive_renaming(intake_runtime, data, kind):
    _, _, settings, _, root = intake_runtime
    source = root / 'renamed.bin'
    source.write_bytes(data)
    assert profile(source, settings)['kind'] == kind


def test_generic_compound_document_is_not_misidentified_as_a_jump_list(intake_runtime):
    _, _, settings, _, root = intake_runtime
    source = root / 'misleading.automaticDestinations-ms'
    source.write_bytes(bytes.fromhex('d0cf11e0a1b11ae1') + b'\0' * 512)
    assert profile(source, settings)['kind'] == 'compound'


@pytest.mark.parametrize(('kind', 'mime'), [('unknown', 'application/octet-stream'),
                         ('content', 'application/x-ms-evtx'), ('text', 'text/plain')])
@pytest.mark.parametrize(('chosen', 'expected'), [('memory_dump', 'memory'), ('disk_image', 'disk')])
def test_acquisition_context_takes_precedence_over_generic_magic_guess(kind, mime, chosen, expected):
    # Raw memory can contain bytes libmagic mistakes for another file (the real
    # Citadel DC01 acquisition is reported as Windows Event Trace Log).
    observed = {'kind': kind, 'mime': mime, 'basis': 'Native file / libmagic content identification'}
    result = interpretation({'type': chosen, 'type_basis': 'analyst'}, observed)
    assert result['kind'] == expected and result['mime'] == mime
    assert observed['kind'] == kind  # Retain the original intake observation.
    assert interpretation({'type': chosen, 'type_basis': 'content'}, observed)['kind'] == kind


@pytest.mark.parametrize('kind', ['pdf', 'ewf', 'evtx', 'registry', 'sqlite', 'compound'])
def test_acquisition_context_does_not_override_explicit_format_checks(kind):
    result = interpretation({'type': 'memory_dump', 'type_basis': 'analyst'}, {'kind': kind})
    assert result['kind'] == kind and 'differs' in result['note']


def test_upload_replays_received_bytes_and_completion_is_idempotent(intake_runtime):
    client, repo, settings, case, _ = intake_runtime
    contents = b'%PDF-1.7\n evidence uploaded from a browser'
    base = upload(intake_runtime, [('image.raw', contents)], primary=0,
                  info={'expected_sha256': hashlib.sha256(contents).hexdigest(), 'custodian': 'Transfer examiner'})
    assert put(client, base, 0, 0, contents[:10]).json['offset'] == 10
    assert client.post(base + '/complete').status_code == 400
    # Resume may overlap a persisted partial chunk after a network interruption.
    assert put(client, base, 0, 0, contents[:20]).json['offset'] == 20
    assert put(client, base, 0, 0, b'wrong').status_code == 409
    assert put(client, base, 0, 20, contents[20:]).json['offset'] == len(contents)
    first = client.post(base + '/complete')
    assert first.status_code == 202, first.json
    assert client.post(base + '/complete').json['run_id'] == first.json['run_id']
    assert len(repo.runs()) == 1
    item = first.json['artifact']
    assert client.post('/api/strings/run', json={'case_id': case, 'source_path': item['path']}).status_code == 400
    Worker(repo, settings).run_once()
    item = repo.case(case)['artifacts'][0]
    assert item['hash'] == hashlib.sha256(contents).hexdigest()
    assert item['profile']['kind'] == 'pdf' and item['status'] == 'ready'
    assert Path(item['path']).read_bytes() == contents
    assert not Path(item['path']).stat().st_mode & 0o222
    assert_chain(repo.custody(case, item['id']))


def test_uploaded_collection_hashes_every_file(intake_runtime):
    client, repo, settings, case, _ = intake_runtime
    files = [('empty', b''), ('a.txt', b'one'), ('b.txt', b'two')]
    base = upload(intake_runtime, files)
    for index, (_, data) in enumerate(files):
        if data:
            assert put(client, base, index, 0, data).status_code == 200
    response = client.post(base + '/complete')
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    item = repo.case(case)['artifacts'][0]
    assert item['status'] == 'ready' and item['profile']['kind'] == 'directory'
    assert len(item['manifest']) == 3
    assert item['hash'] == manifest_hash(item['manifest'])


def test_upload_rejects_unsafe_paths_wrong_cases_and_excess_bytes(intake_runtime):
    client, repo, settings, case, _ = intake_runtime
    for name in ['../escape', '/absolute', 'a/b', 'a\\b', '.', '..', 'bad\0name']:
        response = client.post(f'/api/case/{case}/uploads', json={'files': [{'name': name, 'size': 1}]})
        assert response.status_code == 400
    base = upload(intake_runtime, [('source', b'123')], primary=0)
    assert put(client, base, 0, 0, b'1234').status_code == 409
    assert put(client, base, 0, 1, b'1').status_code == 409
    assert put(client, base, 0, 0, b'1' * (4 * 1024 ** 2 + 1)).status_code == 413
    assert client.get(base.replace(case, 'another')).status_code == 400
    assert client.delete(base).status_code == 200
    assert client.get(base).json['status'] == 'discarded'
    assert client.post(base + '/complete').status_code == 400
    assert repo.runs() == []


def test_case_creation_has_no_separate_evidence_path(intake_runtime):
    client, repo, _, _, root = intake_runtime
    response = client.post('/cases', data={'name': 'obsolete intake', 'source_path': str(root / 'file')})
    assert response.status_code == 400
    assert len(repo.cases()) == 1


def test_unrelated_upload_files_cannot_be_left_out_of_primary_manifest(intake_runtime):
    client, repo, *_ = intake_runtime
    base = upload(intake_runtime, [('first.txt', b'one'), ('hidden.txt', b'two')], primary=0)
    put(client, base, 0, 0, b'one')
    put(client, base, 1, 0, b'two')
    response = client.post(base + '/complete')
    assert response.status_code == 400 and 'collected directory' in response.json['error']
    assert repo.runs() == []


def test_cancelled_and_recovered_intake_cannot_leave_pending_evidence(intake_runtime):
    client, repo, settings, case, root = intake_runtime
    source = root / 'sample'
    source.write_bytes(b'sample')
    queued = client.post(f'/api/case/{case}/artifacts', json={'path': str(source)}).json
    assert client.post(f"/api/run/{queued['run_id']}/cancel").json['status'] == 'cancelled'
    assert repo.case(case)['artifacts'][0]['status'] == 'failed'
    retry = client.post(f"/api/case/{case}/evidence/{queued['artifact']['id']}/verify").json
    repo.claim()
    Worker(repo, settings).recover()
    assert repo.run(retry['run_id'])['status'] == 'interrupted'
    assert repo.case(case)['artifacts'][0]['status'] == 'failed'
    assert_chain(repo.custody(case, queued['artifact']['id']))


def test_case_and_type_changes_do_not_modify_original_profile(intake_runtime):
    client, repo, _, case, root = intake_runtime
    source = root / 'ambiguous'
    source.write_bytes(b'\0' * 4096)
    item, _ = register(intake_runtime, source)
    response = client.post(f"/case/{case}/evidence/{item['id']}/type", data={'type': 'memory_dump', 'custodian': 'Examiner 2'})
    assert response.status_code == 302
    current = repo.case(case)['artifacts'][0]
    assert current['profile']['kind'] == 'unknown' and current['hash'] == item['hash']
    assert repo.custody(case, item['id'])['events'][-1]['details']['after']['type'] == 'memory_dump'
