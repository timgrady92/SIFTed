"""Persistence, upgrade compatibility and safe authoring for the shared reference catalog."""
import copy
import json
import sqlite3

import pytest

from app import create_app
from sifted_core.reference import GuideHTML, builtin_catalog, validate
from sifted_core.storage import Repository


@pytest.fixture
def reference_app(tmp_path):
    settings = {'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'reference.db'),
                'SIFTED_INPUT_ROOTS': [str(tmp_path)], 'SIFTED_OUTPUT_ROOTS': [str(tmp_path)]}
    return create_app(settings), settings


def glossary_payload(name='Cloud audit cache'):
    return {'kind': 'glossary', 'section': 'artifacts', 'category': 'custom', 'data': {
        'name': name, 'takeaway': 'A local audit trail.', 'what': 'A cache of cloud activity.',
        'why': 'May corroborate remote access.', 'question': 'Who accessed this account?',
        'location': ['/cases/cloud/cache.db'], 'corroborate': ['Provider audit logs'],
        'keyFields': ['actor: account identifier'], 'os': ['cross']}}


def guide_payload(key='prefetch'):
    return {'kind': 'guide', 'section': 'hypothesis', 'category': 'custom', 'data': {
        'title': 'Investigate cloud audit activity', 'description': 'Correlate a local cache with provider logs.',
        'keywords': 'audit cache cloud',
        'body': f'<div class="guide-group"><div class="guide-group-header">Evidence</div><p>Review <span class="artifact-link" data-artifact="{key}">the audit cache</span>.</p><ol><li><strong>Corroborate</strong> with provider logs.</li></ol><p><code>actor</code> may be incomplete.</p></div>'}}


def test_upgrade_keeps_existing_cases_and_custom_content_survives_restart(reference_app):
    app, settings = reference_app
    repo = Repository(settings['SIFTED_DATABASE_PATH'])
    repo.add_case({'id': 'existing-case', 'name': 'Existing case', 'artifacts': []})
    with sqlite3.connect(repo.path) as db:
        db.execute('DROP TABLE reference_content')
        db.execute('PRAGMA user_version=2')
    client = app.test_client()
    entry = client.post('/api/reference', json=glossary_payload()).json['entry']
    guide = client.post('/api/reference', json=guide_payload(entry['id'])).json['entry']
    restarted = create_app(settings).test_client()
    catalog = restarted.get('/api/reference').json
    records = {item['id']: item for item in catalog['records']}
    assert len(records) == 236 and records[entry['id']]['data']['name'] == 'Cloud audit cache'
    assert f'data-artifact="{entry["id"]}"' in records[guide['id']]['html']
    assert 'role="link" tabindex="0"' in records[guide['id']]['html']
    assert Repository(repo.path).case('existing-case')['name'] == 'Existing case'
    assert restarted.get('/guides').status_code == 200
    assert entry['id'].encode() in restarted.get('/glossary').data


def test_builtin_content_is_complete_and_editing_does_not_change_shipped_defaults(reference_app):
    app, _ = reference_app
    client = app.test_client()
    catalog = client.get('/api/reference').json
    assert len(catalog['records']) == 234
    guides = [r for r in catalog['records'] if r['kind'] == 'guide']
    assert len(guides) == 22
    assert {s: sum(r['section'] == s for r in guides) for s in ('hypothesis', 'artifact')} == {'hypothesis': 11, 'artifact': 11}
    known = {r['id'] for r in catalog['records'] if r['kind'] == 'glossary'}
    with app.app_context():
        for record in catalog['records']:
            assert validate({key: record[key] for key in ('kind', 'section', 'category', 'data')})
    for guide in guides:
        assert GuideHTML(known).result(guide['data']['body'])
    original = next(r for r in builtin_catalog()['records'] if r['id'] == 'prefetch')
    update = {key: copy.deepcopy(original[key]) for key in ('kind', 'section', 'category', 'data')}
    update['data']['what'] = 'Locally reviewed definition'
    response = client.put('/api/reference/prefetch', json={**update, 'revision': 0})
    assert response.status_code == 200 and response.json['entry']['revision'] == 1
    assert original['data']['what'] != 'Locally reviewed definition'
    assert client.put('/api/reference/prefetch', json={**update, 'revision': 0}).status_code == 409
    update['data']['name'] = 'Prefetch (reviewed)'
    saved = client.put('/api/reference/prefetch', json={**update, 'revision': 1})
    assert saved.status_code == 200 and saved.json['entry']['id'] == 'prefetch'


@pytest.mark.parametrize('body', [
    '<script>alert(1)</script>', '<p onclick="alert(1)">Text</p>',
    '<img src=x onerror=alert(1)>', '<a href="javascript:alert(1)">Click</a>',
    '<a href="//evil.example">Click</a>', '<span data-artifact="missing">Unknown entry</span>',
    '<div><p>Unclosed', '<iframe src="/cases"></iframe>',
    '<a href="https://[">Malformed address</a>',
])
def test_rich_content_rejects_executable_html_and_broken_links(reference_app, body):
    app, _ = reference_app
    client = app.test_client()
    payload = guide_payload()
    payload['data']['body'] = body
    assert client.post('/api/reference', json=payload).status_code == 400
    assert len(client.get('/api/reference').json['records']) == 234


def test_preview_and_saved_renderer_match_and_plain_fields_are_escaped(reference_app):
    app, _ = reference_app
    client = app.test_client()
    payload = glossary_payload('</script><script>alert(1)</script>')
    payload['data']['databases'] = {'Audit': [{'file': 'cache.db', 'tables': 'events', 'timestamps': 'Unix seconds'}]}
    payload['data']['eventLogs'] = {'Provider': [{'id': '42', 'log': 'Audit', 'meaning': 'Login'}]}
    preview = client.post('/api/reference/preview', json=payload)
    assert preview.status_code == 200
    assert len(client.get('/api/reference').json['records']) == 234
    saved = client.post('/api/reference', json=payload).json['entry']
    assert saved['html'] == preview.json['entry']['html']
    assert '<script>' not in saved['html'] and '&lt;script&gt;' in saved['html']
    assert all(text in saved['html'] for text in ('cache.db', 'Unix seconds', 'Related Event IDs'))
    page = client.get('/glossary').data
    assert b'</script><script>alert(1)</script>' not in page
    assert b'\\u003cscript\\u003e' in page


@pytest.mark.parametrize('payload', [None, [], {'kind': []}, {'kind': 'guide', 'section': []},
                                    {**glossary_payload(), 'category': []},
                                    {**glossary_payload(), 'unexpected': 'field'}])
def test_invalid_payloads_are_bounded(reference_app, payload):
    app, _ = reference_app
    response = app.test_client().post('/api/reference', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 400


def test_cross_origin_forms_and_oversized_bodies_do_not_write(reference_app):
    app, _ = reference_app
    client = app.test_client()
    assert client.post('/api/reference', data={'title':'form'}).status_code == 415
    assert client.post('/api/reference', json=glossary_payload(), headers={'Origin':'https://elsewhere.test'}).status_code == 403
    payload = glossary_payload('x' * 300000)
    assert client.post('/api/reference', json=payload).status_code == 413
    assert len(client.get('/api/reference').json['records']) == 234


@pytest.mark.parametrize('section,data', [
    ('registry', {'key':'NTUSER.DAT\\Software\\Zephyr', 'purpose':'Tenant account cache', 'lookFor':'Account identifiers'}),
    ('persistence', {'path':'~/.config/zephyr/startup', 'scope':'User', 'trigger':'Login', 'notes':'May launch an authorized agent'}),
    ('events', {'event_id':'90210', 'log':'Zephyr-Audit', 'name':'Tenant access', 'lookFor':'Actor and source address'}),
])
def test_every_glossary_section_can_be_authored_and_linked(reference_app, section, data):
    app, settings = reference_app
    client = app.test_client()
    saved = client.post('/api/reference', json={'kind':'glossary', 'section':section, 'category':'custom', 'data':data})
    assert saved.status_code == 201
    entry = saved.json['entry']
    assert entry['what'] and entry['why'] and entry['html']
    guide = client.post('/api/reference', json=guide_payload(entry['id']))
    assert guide.status_code == 201
    restarted = create_app(settings).test_client().get('/api/reference').json
    assert next(r for r in restarted['records'] if r['id'] == entry['id'])['data'] == data
