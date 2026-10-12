"""Unmodified public evidence through upload, custody, profiles and native analysis."""
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from sifted_core.worker import Worker
from sifted_core.zimmerman import resolve_ez_tool
from test_evidence_intake import intake_runtime as intake_runtime, upload, put, assert_chain
from test_evidence_workspace import view


DEMOS = Path(__file__).resolve().parent.parent / 'demos'
SAMPLES = json.loads((DEMOS / 'manifest.json').read_text())['files']


def uploaded(runtime, sample, name=None):
    client, repo, settings, case, _ = runtime
    data = (DEMOS / 'evidence' / sample['path']).read_bytes()
    base = upload(runtime, [(name or Path(sample['path']).name, data)], primary=0,
                  info={'custodian': 'Public corpus validation', 'source': sample['source'],
                        'expected_sha256': sample['sha256']})
    for offset in range(0, len(data), 4 * 1024 ** 2):
        response = put(client, base, 0, offset, data[offset:offset + 4 * 1024 ** 2])
        assert response.status_code == 200, response.json
    response = client.post(base + '/complete')
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    result = repo.run(response.json['run_id'])
    assert result['status'] == 'success', result.get('error')
    return next(x for x in repo.case(case)['artifacts'] if x['id'] == response.json['artifact']['id'])


def execute(runtime, item, tool, **options):
    client, repo, settings, case, _ = runtime
    response = client.post(f'/api/{tool}/run', json={
        'case_id': case, 'source_path': item['path'], 'workspace_input': 'e:' + item['id'], **options})
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    result = repo.run(response.json['run_id'])
    assert result['status'] == 'success', result.get('error')
    assert result['input_sha256'] == item['hash']
    assert_chain(repo.custody(case, item['id']))
    assert hashlib.sha256(Path(item['path']).read_bytes()).hexdigest() == item['hash']
    return result


def test_demo_manifest_matches_every_bundled_byte():
    paths = {p.relative_to(DEMOS / 'evidence').as_posix() for p in (DEMOS / 'evidence').rglob('*') if p.is_file()}
    assert paths == {x['path'] for x in SAMPLES}
    for sample in SAMPLES:
        data = (DEMOS / 'evidence' / sample['path']).read_bytes()
        assert len(data) == sample['size_bytes']
        assert hashlib.sha256(data).hexdigest() == sample['sha256']
        assert sample['source'].startswith('https://') and sample['modified'] is False
    assert (DEMOS / 'SHA256SUMS').read_text() == ''.join(f"{x['sha256']}  {x['path']}\n" for x in SAMPLES)


@pytest.mark.parametrize('sample', SAMPLES, ids=lambda s: s['path'])
@pytest.mark.parametrize('transport', ['upload', 'workstation'])
def test_real_content_has_same_verified_profile_after_renaming(intake_runtime, sample, transport):
    client, repo, settings, case, root = intake_runtime
    if transport == 'upload':
        item = uploaded(intake_runtime, sample, name='unhelpful name.data')
    else:
        source = root / 'unhelpful name.data'
        shutil.copyfile(DEMOS / 'evidence' / sample['path'], source)
        response = client.post(f'/api/case/{case}/artifacts', json={
            'path': str(source), 'expected_sha256': sample['sha256'], 'custodian': 'Public corpus validation'})
        assert response.status_code == 202, response.json
        Worker(repo, settings).run_once()
        item = repo.case(case)['artifacts'][0]
    assert item['status'] == 'ready'
    assert item['hash'] == sample['sha256']
    assert item['profile']['kind'] == sample['kind']
    assert_chain(repo.custody(case, item['id']))
    assert item['manifest'][0]['sha256'] == sample['sha256']


@pytest.mark.live
@pytest.mark.parametrize('path,parser,options,count', [
    ('windows/Amcache.hve', 'amcacheparser', {}, 166),
    ('windows/System.evtx', 'evtxecmd', {}, 5009),
    ('windows/f01b4d95cf55d32a.automaticDestinations-ms', 'jlecmd', {}, 9),
    ('windows/NeroInfoTool.lnk', 'lecmd', {}, 1),
    ('windows/$I103S5F.jpg', 'rbcmd', {}, 1),
    ('browser/History', 'sqlecmd', {'maps': ['Windows_ChromiumBrowser_KeywordSearches.smap']}, 3),
])
def test_uploaded_public_artifacts_have_known_native_findings(intake_runtime, path, parser, options, count):
    capability = resolve_ez_tool(parser, intake_runtime[2])
    if not capability['installed']:
        pytest.skip(capability['error'])
    item = uploaded(intake_runtime, next(x for x in SAMPLES if x['path'] == path))
    result = execute(intake_runtime, item, 'eric-zimmerman', tool_id=parser, **options)
    records = []
    for table in result['analysis']['tables']:
        with (Path(result['output_path']) / table['file']).open(encoding='utf-8-sig', newline='') as handle:
            records.extend(csv.DictReader(handle))
    if count is not None:
        assert len(records) == count
    assert records
    if parser == 'amcacheparser':
        assert any(row.get('Name') == '7z1900-x64.exe' and row.get('SHA1') == '9fa11a63b43f83980e0b48dc9ba2cb59d545a4e8' for row in records)
    elif parser == 'evtxecmd':
        assert records[0]['EventId'] == '7036' and records[0]['Channel'] == 'System'
        assert records[0]['TimeCreated'] == '2010-11-21 03:55:59.6264271'
    elif parser == 'lecmd':
        assert records[0]['LocalPath'].endswith(r'\Nero\Nero 9\Nero InfoTool\InfoTool.exe')
        assert '-ScParameter=30002' in records[0]['Arguments']
    elif parser == 'jlecmd':
        assert any(row['EntryNumber'] == '7' and row['Hostname'] == 'desktop-annfp9d'
                   and row['Path'].endswith('Temp') for row in records)
    elif parser == 'rbcmd':
        assert records[0]['FileName'] == r'C:\Users\random\Downloads\bunnies.jpg'
        assert records[0]['FileSize'] == '222255'
        assert records[0]['DeletedOn'] == '2016-06-29 21:37:45.6180000'
    elif parser == 'sqlecmd':
        assert result['analysis']['engine'] == 'SIFTed SQLite maps'
        assert {row['KeywordSearchTerm'] for row in records} == {'funny cats', 'really really funny cats', 'funnycats.exe'}
        with sqlite3.connect(Path(item['path']).as_uri() + '?mode=ro', uri=True) as db:
            assert db.execute('SELECT count(*) FROM visits').fetchone()[0] == 69
            assert db.execute('SELECT full_path FROM downloads ORDER BY id').fetchall() == [
                ('/home/john/Downloads/funcats_scr.exe',), ('/home/john/Downloads/Cats Demo.exe',)]


@pytest.mark.live
def test_uploaded_camera_image_recovers_fragmented_photo_with_known_hash(intake_runtime):
    if not all(shutil.which(tool) for tool in ('mmls', 'fls', 'icat')):
        pytest.skip('Sleuth Kit is required for native camera analysis.')
    sample = next(x for x in SAMPLES if x['kind'] == 'ewf')
    item = uploaded(intake_runtime, sample)
    execute(intake_runtime, item, 'mmls')
    client, repo, _, case, _ = intake_runtime
    key = 'e:' + item['id']
    card = next(x for x in view(client, case, key)['journey'] if x['offset_sector'] == 51)
    inventory = execute(intake_runtime, item, 'fls', **{
        k: v for k, v in card['inventory_payload'].items() if k not in {'case_id', 'source_path', 'workspace_input'}})
    text = (Path(inventory['output_path']) / 'fls.txt').read_text()
    assert 'IMG_0044.JPG' in text and '_MG_0025.JPG' in text
    triage = view(client, case, key, tab='triage', context_run_id=inventory['id'],
                  scope='filesystem', q='IMG_0044.JPG')['triage']
    selected = next(row for row in triage['rows'] if row['name'] == 'IMG_0044.JPG')
    extracted = execute(intake_runtime, item, 'icat', **{
        k: v for k, v in selected['extract_payload'].items() if k not in {'case_id', 'source_path', 'workspace_input'}})
    data = (Path(extracted['output_path']) / extracted['analysis']['derived_file']).read_bytes()
    # Independent upstream report: this photograph spans three discontiguous extents.
    assert len(data) == 105195
    assert hashlib.sha1(data).hexdigest() == '916a88a00c58b7a566711acd25e61d549df5d303'
    assert len(repo.custody(case, item['id'])['events']) > 4
