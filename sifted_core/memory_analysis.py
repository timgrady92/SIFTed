"""Guided memory analysis projected from the ordinary Volatility runs.

Profiles describe analytical choices, not separate executors. The installed
plugin catalog, adapter, worker, published results and custody remain canonical.
"""
from . import published, volatility
from .memory_catalog import PROFILES, QUESTIONS, SUPPORTING, action as definition
from .tool_base import ValidationError, executable, normalize


def options_for(spec, installed, pid=None):
    options = dict(spec['options'])
    if spec['pid'] and pid is not None:
        declarations = {o['name']: o for o in installed['plugins'].get(spec['plugin'], {}).get('options', [])}
        kind = declarations.get(spec['pid'], {}).get('type')
        if kind not in {'integer', 'integer_list'}:
            raise ValidationError('The installed plugin does not support this process selector.')
        options[spec['pid']] = pid if kind == 'integer' else [pid]
    return options


def report_for(run, plugin):
    if not run or run['status'] != 'success' or run['tool'] != 'volatility':
        return None
    return next((r['file'] for r in run.get('plugin_results', [])
                 if r['plugin'] == plugin and r['status'] == 'success' and r['file'].endswith(('.json', '.jsonl'))), None)


def inventory_report(run, plugin):
    if plugin not in {p['inventory'] for p in PROFILES.values()}:
        raise ValidationError('Choose a process inventory plugin.')
    report = report_for(run, plugin)
    if not report or run['plan']['parameters'].get('plugin_options', {}).get(plugin):
        raise ValidationError('Build an unfiltered, structured process inventory before selecting a process.')
    return report


def validate_process(plan, repository, settings, case_id):
    ref = plan.parameters.get('process_ref')
    if 'process_ref' not in plan.parameters:
        return None
    if (not isinstance(ref, dict) or set(ref) != {'run_id', 'plugin', 'row_id'}
            or not isinstance(ref['run_id'], str) or not isinstance(ref['plugin'], str)
            or type(ref['row_id']) is not int or ref['row_id'] < 1):
        raise ValidationError('Process selection requires an inventory run, plugin and row.')
    context = repository.run(ref['run_id'])
    if (not case_id or not context or context.get('case_id') != case_id
            or normalize(context['source_path']) != plan.source or not context.get('input_sha256')):
        raise ValidationError('Process inventory must belong to this case and memory image.')
    report = inventory_report(context, ref['plugin'])
    selection = published.page(context, report, repository, settings, selected=ref['row_id'], limit=0)['selected']
    pid = selection['values'].get('PID')
    if type(pid) is not int or not 0 <= pid <= 2 ** 32 - 1:
        raise ValidationError('This result does not contain a usable process ID.')
    profile = next(p for p in PROFILES.values() if p['inventory'] == ref['plugin'])
    params = plan.parameters
    installed = volatility.discover(settings)
    matched = False
    for spec in profile['process']:
        if params['plugins'] != [spec['plugin']]:
            continue
        expected = options_for(spec, installed, pid)
        supplied = params['plugin_options'].get(spec['plugin'], {})
        fields = {field['name'] for field in spec['fields']}
        if (set(params['plugin_options']) == {spec['plugin']}
                and {k: v for k, v in supplied.items() if k not in fields} == expected
                and all(isinstance(supplied.get(k), str) and supplied[k].strip() for k in fields)):
            matched = True
            break
    if not matched:
        raise ValidationError('Examination options do not match the selected process.')
    return {**ref, 'pid': pid, 'record': selection['values'], 'inventory_sha256': context['input_sha256']}


def journey(item, observed, runs, case_id, repository, settings, *, operating_system='', inventory_id='', query='', offset=0, row_id=None, question='network'):
    matching = [r for r in runs if normalize(r['source_path']) == normalize(item['path'])
                and r.get('input_sha256') == item.get('hash') and item.get('hash')]
    if not operating_system:
        operating_system = next((os for r in matching for os, p in PROFILES.items()
                                 if report_for(r, p['inventory'])), 'windows')
    if operating_system not in PROFILES or question not in QUESTIONS:
        raise ValidationError('Choose an available acquisition context and investigation question.')
    profile = PROFILES[operating_system]
    reason = None
    try:
        installed = volatility.discover(settings)
    except ValidationError as exc:
        installed, reason = {'plugins': {}}, str(exc)
    base = {'case_id': case_id, 'source_path': item['path'], 'workspace_input': item['key']}
    vol_base = {**base, 'renderer': 'jsonl'}
    previous = next((r for r in matching if r['tool'] == 'volatility' and r['status'] == 'success'
                     and any(p.startswith(operating_system + '.') for p in r['plan']['parameters']['plugins'])), None)
    if previous:
        vol_base.update({k: previous['plan']['parameters'][k] for k in ('symbol_path', 'offline')})
    facts = {}
    info = next((r for r in matching if report_for(r, profile['identify'])), None)
    if info and operating_system == 'windows':
        try:
            with published.artifact(info, report_for(info, profile['identify']), repository, settings) as handle:
                facts = {r.get('Variable'): r.get('Value') for r in published.records(handle, report_for(info, profile['identify']))}
        except ValidationError:
            pass  # Unverified facts never unlock a version-specific examination.

    def action(spec, pid=None, ref=None):
        tool, plugin = spec['tool'], spec['plugin']
        unavailable, options, fields = None, dict(spec['options']), []
        if tool == 'volatility':
            try:
                options = options_for(spec, installed, pid)
            except ValidationError as exc:
                unavailable = str(exc)
            payload = {**vol_base, 'plugins': [plugin], 'plugin_options': {plugin: options}}
            if ref:
                payload['process_ref'] = ref
            declared_plugin = installed['plugins'].get(plugin)
            unavailable = reason or (f'{plugin} is unavailable in the installed Volatility.' if not declared_plugin else unavailable)
            if declared_plugin:
                declared = {o['name']: o for o in declared_plugin['options']}
                provided = set(options) | {f['name'] for f in spec['fields']}
                if (provided - declared.keys() or any(o['required'] and o['name'] not in provided for o in declared_plugin['options'])
                        or any(declared[k]['type'] != ('boolean' if type(v) is bool else 'integer' if type(v) is int else 'integer_list') for k, v in options.items() if k in declared)
                        or any(declared.get(f['name'], {}).get('type') != f['native_type'] for f in spec['fields'])):
                    unavailable = 'The installed plugin requires different options. Use the plugin examiner.'
            fields = [{**field, 'path': ['plugin_options', plugin, field['name']]} for field in spec['fields']]
            for field in fields:
                source = field.get('choices_from')
                if not source:
                    continue
                choices = []
                context = next((r for r in matching if report_for(r, source['plugin'])
                                and not r['plan']['parameters'].get('plugin_options', {}).get(source['plugin'])), None)
                if context:
                    try:
                        report = report_for(context, source['plugin'])
                        with published.artifact(context, report, repository, settings) as handle:
                            choices = sorted({row[source['column']] for row in published.records(handle, report)
                                              if isinstance(row.get(source['column']), str) and row[source['column']].strip()})
                    except ValidationError:
                        unavailable = 'The recorded choices could not be verified. Repeat the listing before extraction.'
                field['choices'] = [('', 'Choose a recorded hive'), *((value, value) for value in choices)]
                if not choices:
                    unavailable = unavailable or 'Locate registry hives first to choose a hive for extraction.'
            if spec['min_windows']:
                major = str(facts.get('NtMajorVersion', ''))
                if not major.isdecimal():
                    unavailable = 'Identify the Windows version in Prepare before examining network objects.'
                elif int(major) < spec['min_windows']:
                    unavailable = 'These plugins require Windows Vista / Server 2008 or later. This capture needs an older-network parser; strings and feature matches are only leads.'
            result = next((r for r in matching if report_for(r, plugin)
                           and {k: v for k, v in r['plan']['parameters'].get('plugin_options', {}).get(plugin, {}).items() if k not in {f['name'] for f in fields}} == options
                           and r['plan']['parameters'].get('process_ref') == ref), None)
        else:
            payload = {**base, **options}
            try:
                executable(tool, ['bulk_extractor' if tool == 'bulk-extractor' else tool], settings)
            except ValidationError as exc:
                unavailable = str(exc)
            result = next((r for r in matching if r['tool'] == tool and r['status'] == 'success'
                           and all(r['plan']['parameters'].get(k) == v for k, v in options.items())), None)
        return {**spec, 'payload': payload, 'fields': fields, 'run_id': result['id'] if result else None,
                'reason': (observed.get('note') or 'Verify evidence before analysis.') if not observed['available'] else unavailable}

    inventories = [r for r in matching if report_for(r, profile['inventory'])
                   and not r['plan']['parameters'].get('plugin_options', {}).get(profile['inventory'])]
    context = next((r for r in inventories if r['id'] == inventory_id), None) if inventory_id else next(iter(inventories), None)
    if inventory_id and not context:
        raise ValidationError('Process inventory must be a successful, unfiltered run for this evidence baseline and OS.')
    specs = profile['investigations'] + SUPPORTING
    questions = {k: v for k, v in QUESTIONS.items() if any(s['group'] == k for s in specs)}
    if question not in questions:
        question = next(iter(questions))
    model = {'os': operating_system, 'systems': {k: v['label'] for k, v in PROFILES.items()},
             'identify': action(definition('identify', 'Identify image' if operating_system == 'windows' else 'Find kernel banners', profile['identify'])),
             'inventory_action': action(definition('inventory', 'Build process inventory', profile['inventory'])),
             'checks': [action(definition(plugin, label, plugin)) for label, plugin in profile['checks']],
             'inventory': context, 'inventories': [{'id': r['id'], 'created_at': r['created_at']} for r in inventories],
             'processes': None, 'process_actions': [], 'error': None, 'questions': questions, 'question': question,
             'investigations': [action(spec) for spec in specs if spec['group'] == question]}
    if context:
        try:
            table = published.page(context, inventory_report(context, profile['inventory']), repository, settings,
                                   query=query, offset=offset, selected=row_id)
            model['processes'] = table
            if table['selected']:
                pid = table['selected']['values'].get('PID')
                if type(pid) is int and 0 <= pid <= 2 ** 32 - 1:
                    ref = {'run_id': context['id'], 'plugin': profile['inventory'], 'row_id': row_id}
                    model['process_actions'] = [action(spec, pid, ref) for spec in profile['process']]
        except ValidationError as exc:
            model['error'] = str(exc)
    return model


def process_rows(context, repository, settings):
    """Unique PID-to-row observations, never a claim of object identity."""
    if not context:
        return {}
    plugin = next((p['inventory'] for p in PROFILES.values() if report_for(context, p['inventory'])), None)
    report = inventory_report(context, plugin)
    found = {}
    with published.artifact(context, report, repository, settings) as handle:
        for ordinal, row in enumerate(published.records(handle, report), 1):
            pid = row.get('PID')
            if type(pid) is int and 0 <= pid <= 2 ** 32 - 1:
                found[pid] = None if pid in found else ordinal
    return found
