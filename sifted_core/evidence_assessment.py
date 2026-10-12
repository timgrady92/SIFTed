"""Combine native structural observations into a recorded workflow decision."""
import json
from pathlib import Path

from .tool_base import ValidationError, executable
from .volatility import runtime

PROBE = Path(__file__).with_name('native_profile.py')
ACQUISITIONS = {'unknown', 'content', 'text', 'disk', 'filesystem', 'ewf', 'memory'}


def assess(path, observed, settings, execute, image_paths=None):
    """Runs only during verified worker intake, never from a workspace render.

    Extensions may prioritize probes; they cannot create a positive result or
    exclude a probe. Negative, unavailable and timed-out probes remain distinct.
    """
    if observed['kind'] not in ACQUISITIONS:
        return
    size = observed['signature'][2]
    names = ['disk'] if size >= 512 else []
    if (size >= 1024 ** 2 and observed['kind'] != 'ewf') or observed['kind'] == 'memory':
        names.append('memory')
    if Path(path).suffix.casefold() in {'.mem', '.vmem', '.dmp'}:
        names.sort(key=lambda name: name != 'memory')
    probes = []
    for name in names:
        try:
            if name == 'memory':
                if len(image_paths or [path]) != 1:
                    probes.append({'name': name, 'status': 'inconclusive', 'detail': 'Segmented memory profiling is unavailable.'})
                    continue
                _, interpreter, location = runtime(settings)
                argv = [*interpreter, str(PROBE), name, str(path), location]
            else:
                argv = [*executable('forensic-python', ['/usr/bin/python3'], settings), str(PROBE), name,
                        json.dumps(image_paths or [str(path)])]
            execution, content = execute(name, argv, 25 if name == 'memory' else 10)
            if execution['return_code']:
                result = {'status': 'inconclusive', 'detail': execution['error'] or 'Native profiling did not complete.'}
            else:
                try:
                    result = json.loads(content)
                    if not isinstance(result, dict) or result.get('status') not in {'matched', 'no_match', 'unavailable', 'inconclusive'}:
                        raise ValueError('Invalid native profile result.')
                    supported = {'memory'} if name == 'memory' else {'disk', 'filesystem', 'ewf'}
                    if result['status'] == 'matched' and (result.get('kind') not in supported or not isinstance(result.get('facts'), dict)):
                        raise ValueError('Invalid structural identification.')
                except (ValueError, TypeError) as exc:
                    result = {'status': 'inconclusive', 'detail': str(exc)}
            probes.append({**result, 'name': name, 'execution': execution})
        except ValidationError as exc:
            probes.append({'name': name, 'status': 'unavailable', 'detail': str(exc)})
    matches = [probe for probe in probes if probe['status'] == 'matched']
    assessment = {'probes': probes, 'signature_kind': observed['kind'], 'extension_hint': Path(path).suffix.casefold(),
                  'status': 'supported' if observed['kind'] not in {'unknown', 'content', 'text'} else 'unresolved'}
    kinds = {probe['kind'] for probe in matches}
    if len(kinds) > 1:
        assessment['status'] = 'conflict'
        observed.update(kind='unknown', basis='Conflicting native structure observations',
                        note='More than one acquisition structure was detected. Select the intended workflow.')
    elif matches:
        match = matches[0]
        assessment['status'] = 'supported'
        observed.update(kind=match['kind'], basis='Native structure validation', note='')
        if match['kind'] == 'memory':
            observed['memory'] = match['facts']
        else:
            observed['disk'] = match['facts']
    observed['assessment'] = assessment
