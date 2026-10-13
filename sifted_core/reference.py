"""One catalog, validation boundary and renderer for shipped and authored reference content."""
from functools import lru_cache
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid

from flask import Blueprint, g, jsonify, render_template, request

from .context import runtime_repository
from .storage import StoreError


reference = Blueprint('reference', __name__)
OS_NAMES = {'windows': 'Windows', 'macos': 'macOS', 'linux': 'Linux', 'cross': 'Cross-platform'}
SECTIONS = {'artifacts': 'Artifacts', 'registry': 'Registry', 'persistence': 'Persistence', 'events': 'Windows Events'}
FIELDS = {
    'artifacts': [('name', 'Name'), ('takeaway', 'Key takeaway'), ('what', 'What it is'),
                  ('why', 'Why it matters'), ('question', 'Analyst question'),
                  ('corroborate', 'Corroborate with'), ('location', 'Where to look'), ('keyFields', 'Key fields to query')],
    'registry': [('key', 'Registry path'), ('purpose', 'Purpose'), ('lookFor', 'What to look for')],
    'persistence': [('path', 'Location'), ('scope', 'Scope'), ('trigger', 'Trigger'), ('notes', 'Interpretation')],
    'events': [('event_id', 'Event ID'), ('log', 'Log or provider'), ('name', 'Event name'), ('lookFor', 'What to look for')],
    'guide': [('title', 'Title'), ('description', 'Summary'), ('keywords', 'Search keywords')],
}
LIST_FIELDS = {'corroborate', 'location', 'keyFields'}
RICH_CLASSES = set('guide-group guide-group-header guide-detail-section guide-detail-label warning guide-detail-text guide-detail-list guide-section guide-header guide-list helper artifact-link ghost'.split())
RICH_TAGS = set('div p h3 h4 ul ol li strong b em i u code pre br a span table thead tbody tr th td blockquote'.split())


class ContentError(ValueError):
    pass


@lru_cache(maxsize=1)
def builtin_catalog():
    catalog = json.loads((Path(__file__).resolve().parent.parent / 'content/builtin.json').read_text())
    known = {record['id'] for record in catalog['records'] if record['kind'] == 'glossary'}
    for record in catalog['records']:
        if record['kind'] == 'guide':
            record['data']['body'] = GuideHTML(known).result(record['data']['body'])
    return catalog


def entries():
    result = {r['id']: {**r, 'revision': 0, 'origin': 'builtin'} for r in builtin_catalog()['records']}
    for record in runtime_repository().reference_content():
        result[record['id']] = {**record, 'origin': 'edited' if record['id'] in result else 'custom'}
    return result


class GuideHTML(HTMLParser):
    """Allow the existing guide vocabulary, never executable markup or arbitrary attributes."""
    def __init__(self, known):
        super().__init__(convert_charrefs=True)
        self.known, self.parts, self.stack = known, [], []

    def handle_starttag(self, tag, attrs):
        if tag not in RICH_TAGS:
            raise ContentError(f'Unsupported guide formatting: {tag}. Paste as plain text instead.')
        attributes = dict(attrs)
        if len(attributes) != len(attrs) or set(attributes) - {'class', 'href', 'target', 'rel', 'data-artifact', 'role', 'tabindex'}:
            raise ContentError('Unsupported guide attributes. Use the editor formatting controls.')
        safe = {}
        if 'class' in attributes:
            classes = (attributes['class'] or '').split()
            if set(classes) - RICH_CLASSES:
                raise ContentError('Unsupported guide style.')
            safe['class'] = ' '.join(classes)
        if 'href' in attributes:
            href = attributes['href'] or ''
            local = href.startswith('/') and not href.startswith('//') and '\\' not in href
            try:
                parsed = urlsplit(href)
            except ValueError as exc:
                raise ContentError('The link URL is malformed.') from exc
            if tag != 'a' or any(ord(c) < 32 for c in href) or not (local or (parsed.scheme in {'http', 'https'} and parsed.netloc)):
                raise ContentError('Links must be HTTP(S) URLs or paths within SIFTed.')
            safe.update(href=href, rel='noopener noreferrer')
        if 'data-artifact' in attributes:
            key = attributes['data-artifact']
            if tag != 'span' or key not in self.known:
                raise ContentError('A glossary link points to an entry that does not exist. Choose a saved entry.')
            safe.update({'class': 'artifact-link', 'data-artifact': key, 'role': 'link', 'tabindex': '0'})
        self.parts.append('<' + tag + ''.join(f' {k}="{escape(v, quote=True)}"' for k, v in safe.items()) + '>')
        if tag != 'br':
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag != 'br':
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == 'br':
            return
        if not self.stack or self.stack.pop() != tag:
            raise ContentError('The guide formatting is incomplete. Check its sections before saving.')
        self.parts.append('</' + tag + '>')

    def handle_data(self, data):
        self.parts.append(escape(data))

    def result(self, body):
        self.feed(body)
        self.close()
        if self.stack or not re.sub('<[^>]*>', '', body).strip():
            raise ContentError('Add guide content with complete formatting before saving.')
        return ''.join(self.parts)


def string(value, label, limit=8000, required=False):
    if not isinstance(value, str) or len(value) > limit or '\x00' in value:
        raise ContentError(f'{label} must be text of at most {limit} characters.')
    value = value.strip()
    if required and not value:
        raise ContentError(f'{label} is required.')
    return value


def validate(payload, current=None):
    if not isinstance(payload, dict) or set(payload) - {'kind', 'section', 'category', 'data', 'revision'}:
        raise ContentError('Use the supported content fields.')
    kind, section = payload.get('kind'), payload.get('section')
    if not isinstance(kind, str) or not isinstance(section, str) or kind not in {'glossary', 'guide'} or section not in (SECTIONS if kind == 'glossary' else {'hypothesis', 'artifact'}):
        raise ContentError('Choose a glossary section or guide type.')
    if current and (kind != current['kind'] or section != current['section']):
        raise ContentError('Content type cannot change after saving. Use it as a template for a new entry.')
    category = payload.get('category')
    if not isinstance(category, str) or category not in builtin_catalog()['categories']['guides' if kind == 'guide' else section]:
        raise ContentError('Choose a category.')
    source = payload.get('data')
    fields = FIELDS['guide' if kind == 'guide' else section]
    extra = {'body'} if kind == 'guide' else {'os', 'databases', 'eventLogs'} if section == 'artifacts' else set()
    if not isinstance(source, dict) or set(source) - ({key for key, _ in fields} | extra):
        raise ContentError('Unsupported fields for this content type.')
    data = {}
    for key, label in fields:
        if key in LIST_FIELDS:
            value = source.get(key, [])
            if not isinstance(value, list) or len(value) > 100:
                raise ContentError(f'{label} must contain at most 100 lines.')
            data[key] = [string(item, label) for item in value if item != '']
        else:
            data[key] = string(source.get(key, ''), label, required=key not in {'keywords', 'question'})
    if kind == 'guide':
        known = {key for key, entry in entries().items() if entry['kind'] == 'glossary'}
        data['body'] = GuideHTML(known).result(string(source.get('body', ''), 'Guide body', 150000, True))
    elif section == 'artifacts':
        operating = source.get('os', [])
        if not isinstance(operating, list) or not operating or any(not isinstance(v, str) or v not in OS_NAMES for v in operating):
            raise ContentError('Select at least one operating system.')
        data['os'] = list(dict.fromkeys(operating))
        for field, columns in [('databases', ['file', 'tables', 'timestamps']), ('eventLogs', ['id', 'log', 'meaning'])]:
            groups = source.get(field, {})
            if not isinstance(groups, dict) or len(groups) > 20:
                raise ContentError('Use at most 20 groups of supporting details.')
            data[field] = {}
            for group, rows in groups.items():
                label = string(group, 'Group name', 120, True)
                if not isinstance(rows, list) or len(rows) > 100:
                    raise ContentError('Use at most 100 rows per group.')
                data[field][label] = []
                for row in rows:
                    if not isinstance(row, dict) or set(row) != set(columns):
                        raise ContentError('Complete every supporting-detail column.')
                    data[field][label].append({key: string(row[key], key, required=True) for key in columns})
    return {'kind': kind, 'section': section, 'category': category, 'data': data}


def describe(record):
    data, section = record['data'], record['section']
    if record['kind'] == 'guide':
        return data['title'], data['description'], data['description']
    if section == 'artifacts':
        return data['name'], data['what'], data['why']
    if section == 'registry':
        return data['key'], data['purpose'], data['lookFor']
    if section == 'persistence':
        return data['path'], data['notes'], f"{data['scope']} · {data['trigger']}"
    return f"{data['event_id']} · {data['name']}", data['lookFor'], data['log']


def present(record):
    title, what, why = describe(record)
    return {**record, 'title': title, 'what': what, 'why': why,
            'html': render_template('_reference_detail.html', entry=record, title=title)}


def catalog():
    return {'categories': builtin_catalog()['categories'], 'records': [present(r) for r in entries().values()]}


def bootstrap():
    if 'reference_catalog' not in g:
        g.reference_catalog = catalog()
    return g.reference_catalog


@reference.before_request
def bound_requests():
    request.max_content_length = 256 * 1024
    if request.method in {'POST', 'PUT'}:
        # JSON-only mutations reject form submissions from unrelated websites.
        if not request.is_json:
            return jsonify(error='Send content as JSON.'), 415
        origin = request.headers.get('Origin')
        if origin and origin != request.host_url.rstrip('/'):
            return jsonify(error='Content must be saved from this SIFTed installation.'), 403


@reference.errorhandler(ContentError)
def invalid(error):
    return jsonify(error=str(error)), 400


@reference.errorhandler(StoreError)
def conflict(error):
    return jsonify(error=str(error)), 409


@reference.get('/api/reference')
def get_catalog():
    response = jsonify(catalog())
    response.headers['Cache-Control'] = 'no-store'
    return response


@reference.get('/reference/new')
@reference.get('/reference/<entry_id>/edit')
def editor(entry_id=None):
    entry = entries().get(entry_id) if entry_id else None
    if entry_id and not entry:
        return 'Content not found.', 404
    return render_template('reference_editor.html', entry=entry, fields=FIELDS, os_names=OS_NAMES, sections=SECTIONS)


@reference.post('/api/reference/preview')
def preview():
    record = validate(request.get_json())
    return jsonify(entry=present({**record, 'id': 'preview', 'revision': 0}))


@reference.post('/api/reference')
@reference.put('/api/reference/<entry_id>')
def save(entry_id=None):
    current = entries().get(entry_id) if entry_id else None
    if entry_id and not current:
        return jsonify(error='Content not found.'), 404
    payload = request.get_json()
    record = validate(payload, current)
    revision = payload.get('revision', 0)
    if type(revision) is not int or revision < 0 or (not current and revision):
        raise ContentError('A valid content revision is required.')
    record['id'] = entry_id or 'user-' + uuid.uuid4().hex
    saved = runtime_repository().save_reference_content(record, revision)
    return jsonify(entry=present(saved)), 200 if current else 201
