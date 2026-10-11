"""Verified inventory browsing, immutable selections and persisted investigation continuity."""
import hashlib
from pathlib import Path

import pytest

from sifted_core.worker import Worker
from test_evidence_workspace import workspace_runtime as workspace_runtime, view, register
from test_integrated_tools import integrated as integrated


def inventory(runtime, *, records=None, **options):
    app, client, repo, settings, source, outputs, case, key = runtime
    if records is not None:
        native = Path(settings.binaries['fls'][1])
        native.write_text('import sys\nif sys.argv[1] == "fls":\n    print(' + repr('\n'.join(records)) + ')\nelse:\n    sys.stdout.buffer.write(b"known bytes")\n')
    response = client.post('/api/fls/run', json={'source_path': str(source), 'case_id': case, 'workspace_input': key,
                                               'offset_sector': 2048, 'recursive': True, **options})
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    run = repo.run(response.json['run_id'])
    assert run['status'] == 'success', run.get('error')
    return run


def test_directory_search_filters_pagination_and_reopening_do_not_queue_work(workspace_runtime):
    run = inventory(workspace_runtime, records=['d/d 12: nested', 'd/d 13: nested/deeper',
                    'r/r 14-128-1: nested/deeper/name <script>.txt', 'r/r * 15(realloc): nested/deleted.txt',
                    *[f'r/r {100+i}: item{i:03}.txt' for i in range(205)]])
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    initial = view(client, case, key, tab='triage')
    assert initial['context']['id'] == run['id']
    triage = initial['triage']
    assert triage['counts'] == {'total': 209, 'deleted': 1, 'reallocated': 1}
    assert len(triage['rows']) == 100 and triage['total'] == 206 and triage['next_url']
    second = client.get(triage['next_url'].replace('/case/', '/api/case/', 1)).json['triage']
    assert second['offset'] == 100 and len(second['rows']) == 100
    assert second['rows'][0]['metadata_payload']['entry_id'] == second['rows'][0]['id']
    third = client.get(second['next_url'].replace('/case/', '/api/case/', 1)).json['triage']
    assert third['offset'] == 200 and len(third['rows']) == 6 and not third['next_url']
    nested = triage['rows'][0]
    directory = client.get(nested['directory_url']).data
    assert b'File triage' in directory
    nested_view = view(client, case, key, tab='triage', directory=nested['id'])['triage']
    assert {row['name'] for row in nested_view['rows']} == {'deeper', 'deleted.txt'}
    deeper = next(row for row in nested_view['rows'] if row['name'] == 'deeper')
    deep = view(client, case, key, tab='triage', directory=deeper['id'])['triage']
    assert [crumb['name'] for crumb in deep['breadcrumbs']] == ['nested', 'deeper']
    searched = view(client, case, key, tab='triage', q='<script>', scope='filesystem')['triage']
    assert searched['total'] == 1 and searched['rows'][0]['address'] == '14-128-1'
    html = client.get(f'/case/{case}/workspace', query_string={'input': key, 'tab': 'triage', 'q': '<script>', 'scope': 'filesystem'}).data
    assert b'name &lt;script&gt;.txt' in html and b'name <script>.txt' not in html
    deleted = view(client, case, key, tab='triage', state='deleted', scope='filesystem')['triage']
    assert deleted['total'] == 1 and deleted['rows'][0]['reallocated']
    assert deleted['rows'][0]['extract_payload']['recover_deleted'] is True
    assert view(client, case, key, tab='triage', q="' OR 1=1 --", scope='filesystem')['triage']['total'] == 0
    assert len(repo.runs()) == 1


@pytest.mark.parametrize('changes', [{'metadata_address': '99'}, {'entry_name': 'different.txt'},
                                   {'recover_deleted': False}, {'entry_id': 999}, {'offset_sector': 0},
                                   {'context_run_id': ''}])
def test_selected_entry_cannot_be_retargeted(workspace_runtime, changes):
    run = inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    triage = view(client, case, key, tab='triage', context_run_id=run['id'])['triage']
    row = next(row for row in triage['rows'] if row['deleted'])
    response = client.post('/api/icat/run', json={**row['extract_payload'], **changes})
    assert response.status_code == 400, response.json
    assert len(repo.runs()) == 1


def test_tampered_inventory_is_rejected_in_view_enqueue_and_execution(workspace_runtime):
    run = inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    row = next(row for row in view(client, case, key, tab='triage')['triage']['rows'] if row['kind'] == 'file')
    data = row['extract_payload']
    created = client.post('/api/icat/run', json=data)
    assert created.status_code == 202
    index = Path(run['output_path'])/'inventory.sqlite3'
    original = index.read_bytes()
    index.write_bytes(original + b'tampered')
    assert 'changed' in view(client, case, key, tab='triage')['triage']['error']
    assert client.post('/api/icat/run', json=data).status_code == 400
    Worker(repo, settings).run_once()
    result = repo.run(created.json['run_id'])
    assert result['status'] == 'error' and 'changed' in result['error']
    assert not (Path(result['output_path'])/data['entry_name']).exists()


def test_inventory_symlink_and_foreign_context_are_rejected(workspace_runtime):
    run = inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    index = Path(run['output_path'])/'inventory.sqlite3'
    saved = index.with_name('saved.sqlite3')
    index.rename(saved)
    index.symlink_to(saved)
    assert 'Unable to read' in view(client, case, key, tab='triage')['triage']['error']
    client.post('/cases', data={'name': 'Other'})
    other = repo.cases()[-1]['id']
    response = client.get(f'/api/case/{other}/workspace', query_string={'input': key, 'tab': 'triage', 'context_run_id': run['id']})
    assert response.status_code == 400


def test_multiple_filesystems_require_selection_and_single_directory_is_labeled(workspace_runtime):
    first = inventory(workspace_runtime)
    second = inventory(workspace_runtime, offset_sector=4096)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    assert view(client, case, key, tab='triage')['triage'] is None
    assert len(view(client, case, key)['journey']) == 2
    explicit = view(client, case, key, tab='triage', context_run_id=second['id'])
    assert explicit['context']['plan']['parameters']['offset_sector'] == 4096
    scoped = inventory(workspace_runtime, directory_inode='12', recursive=False)
    scoped_view = view(client, case, key, tab='triage', context_run_id=scoped['id'])['triage']
    assert scoped_view['directory_inode'] == '12' and not scoped_view['recursive']
    assert all(card['inventory_run_id'] != scoped['id'] for card in view(client, case, key)['journey'])
    assert first['id'] != second['id']


def test_inventory_manifest_hash_and_tool_transcript_remain_authoritative(workspace_runtime):
    run = inventory(workspace_runtime)
    repo = workspace_runtime[2]
    for name in ('fls.txt', 'fls.csv', 'inventory.sqlite3'):
        artifact = next(item for item in repo.artifacts(run['id']) if item['name'] == name)
        assert artifact['complete'] and artifact['sha256'] == hashlib.sha256(Path(artifact['path']).read_bytes()).hexdigest()


def test_guided_directory_and_file_actions_retain_selection_in_provenance(workspace_runtime):
    run = inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    triage = view(client, case, key, tab='triage')['triage']
    directory = next(row for row in triage['rows'] if row['kind'] == 'directory')
    metadata = directory['metadata_payload']
    created = client.post('/api/istat/run', json=metadata)
    assert created.status_code == 202, created.json
    Worker(repo, settings).run_once()
    record = repo.input(created.json['run_id'])
    assert record['context_run_id'] == run['id'] and record['filesystem_entry']['address'] == directory['address']
    assert repo.run(created.json['run_id'])['status'] == 'success'
    forged = {**metadata, 'metadata_address': directory['address'], 'entry_name': 'directory.bin', 'recover_deleted': False}
    assert client.post('/api/icat/run', json=forged).status_code == 400


def test_foreign_inventory_context_cannot_be_used_on_same_path(workspace_runtime):
    run = inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    other, other_key = register(client, repo, source, 'disk_image')
    response = client.get(f'/api/case/{other}/workspace', query_string={'input': other_key, 'tab': 'triage', 'context_run_id': run['id']})
    assert response.status_code == 400 and 'context' in response.json['error']


def test_missing_native_tools_leave_inventory_browsable_and_offer_direct_preparation(workspace_runtime):
    inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    settings.binaries['fsstat'] = ['/missing/fsstat']
    settings.binaries['icat'] = ['/missing/icat']
    settings.binaries['istat'] = ['/missing/istat']
    triage = view(client, case, key, tab='triage')['triage']
    assert triage['rows'] and triage['metadata_reason'] and triage['extract_reason']
    html = client.get(f'/case/{case}/workspace', query_string={'input': key, 'tab': 'triage'}).data
    assert triage['extract_reason'].encode() in html and b'disabled title=' in html
    card = view(client, case, key)['journey'][0]
    assert card['stat_reason'] and not card['inventory_reason'] and card['triage_url']


@pytest.mark.parametrize('filters', [{'q': 'x' * 257}, {'scope': 'outside'}, {'state': 'executed'},
                                   {'kind': 'pdf'}, {'directory': '-1'}, {'directory': 'not-an-id'}])
def test_invalid_filters_and_directory_ids_cannot_redirect_triage(workspace_runtime, filters):
    inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    assert view(client, case, key, tab='triage', **filters)['triage']['error']
    assert len(repo.runs()) == 1


def test_derived_files_stay_with_selected_evidence_and_link_back_to_source(workspace_runtime):
    inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    row = next(row for row in view(client, case, key, tab='triage')['triage']['rows'] if row['kind'] == 'file')
    created = client.post('/api/icat/run', json=row['extract_payload'])
    Worker(repo, settings).run_once()
    derived = view(client, case, key, tab='derived')['derived']
    assert len(derived) == 1 and derived[0]['source_run_id'] == created.json['run_id']
    selected = view(client, case, derived[0]['key'])
    assert selected['parent_input']['key'] == key
    other_path = source.with_name('other.img')
    other_path.write_bytes(source.read_bytes())
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(other_path), 'type': 'disk_image'})
    other_key = 'e:' + response.json['artifact']['id']
    assert view(client, case, other_key, tab='derived')['derived'] == []


def test_inventory_storage_is_subject_to_worker_budget(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    settings.max_output_bytes = 12 * 1024
    created = client.post('/api/fls/run', json={'source_path': str(source), 'case_id': case,
                                              'workspace_input': key, 'recursive': True})
    assert created.status_code == 202, created.json
    Worker(repo, settings).run_once()
    run = repo.run(created.json['run_id'])
    assert run['status'] == 'error' and 'budget' in run['error']
    assert all(not item['complete'] for item in repo.artifacts(run['id']))
    assert not view(client, case, key, tab='triage')['triage']


def test_duplicate_directory_paths_require_a_listing_by_metadata_address(workspace_runtime):
    inventory(workspace_runtime, records=['d/d 12: nested', 'd/d * 99: nested', 'r/r 42: nested/file.txt'])
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    triage = view(client, case, key, tab='triage')['triage']
    assert len(triage['rows']) == 2
    for row in triage['rows']:
        assert row['ambiguous_path'] and not row.get('directory_url')
        values = row['listing_payload']
        assert values['directory_inode'] == row['address'] and values['entry_id'] == row['id']
        assert client.post('/api/fls/preview', json=values).status_code == 200
        assert 'Several directory entries' in view(client, case, key, tab='triage', directory=row['id'])['triage']['error']


def test_entry_inspection_reuses_only_work_from_the_same_inventory(workspace_runtime):
    first = inventory(workspace_runtime)
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    selected = next(row for row in view(client, case, key, tab='triage')['triage']['rows'] if row['kind'] == 'file')
    worker = Worker(repo, settings)
    metadata = client.post('/api/istat/run', json=selected['metadata_payload']).json['run_id']
    worker.run_once()
    captured = client.post('/api/icat/run', json=selected['extract_payload']).json['run_id']
    worker.run_once()
    old_view = view(client, case, key, tab='triage', context_run_id=first['id'])
    reopened = next(row for row in old_view['triage']['rows'] if row['id'] == selected['id'])
    assert reopened['metadata_run_id'] == metadata
    assert reopened['captured_key'] == next(item['key'] for item in old_view['derived'] if item['source_run_id'] == captured)
    assert all(not row['metadata_run_id'] and not row['captured_key'] for row in old_view['triage']['rows'] if row['id'] != selected['id'])
    # The same numerical entry ID in another inventory is a different selection.
    second = inventory(workspace_runtime)
    new_view = view(client, case, key, tab='triage', context_run_id=second['id'])
    assert all(not row['metadata_run_id'] and not row['captured_key'] for row in new_view['triage']['rows'])
    assert len(repo.runs()) == 4
