"""Reviewed rules on SIFT's native engines and a real, digest-pinned capture."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from app import create_app
from sifted_core.adapters import compile_plan
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, ValidationError
from sifted_core.volatility import runtime
from sifted_core.worker import Worker
from sifted_core.yara_rules import DEFAULT_RULES
from test_evidence_workspace import register, view
from test_terminal import paste

pytestmark = pytest.mark.live


def test_bundled_rules_compile_on_native_engines():
    try:
        interpreter = runtime(Settings())[1]
    except ValidationError as exc:
        if 'not installed' in str(exc):
            pytest.skip(str(exc))
        raise
    # Only use engines already installed with Volatility; no test-time packages.
    script = '''
import importlib.util, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
source = (root / 'memory.yar').read_text()
manifest = json.loads((root / 'manifest.json').read_text())
names = [name for entry in manifest['files'] for name in entry['rules']]
assert len(names) == len(set(names)) == manifest['rule_count']
engines = []
if importlib.util.find_spec('yara'):
    import yara
    rules = yara.compile(source=source, error_on_warning=True)
    assert {rule.identifier for rule in rules} == set(names)
    engines.append(('yara ' + yara.__version__, lambda data: rules.match(data=data)))
if importlib.util.find_spec('yara_x'):
    import yara_x
    compiler = yara_x.Compiler()
    compiler.add_source(source)
    # Upstream encodes one literal as hex. Preserve it; reject every other warning.
    assert all(warning['code'] == 'text_as_hex' for warning in compiler.warnings()), compiler.warnings()
    compiled = compiler.build()
    engines.append(('yara_x', lambda data: compiled.scan(data).matching_rules))
assert engines, 'No native YARA engine is installed with Volatility.'
for name, scan in engines:
    for file in ['/bin/ls', '/usr/bin/python3', '/usr/bin/ssh', '/usr/sbin/sshd']:
        path = pathlib.Path(file)
        if path.is_file():
            assert not scan(path.read_bytes()), (name, file)
    print(name + ': ' + str(len(names)) + ' rules; no operational warnings or matches on the checked system binaries')
'''
    result = subprocess.run([*interpreter, '-c', script, str(DEFAULT_RULES.parent)],
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    print(result.stdout, end='')


def test_native_bundled_scan_and_pasted_cli_agree(tmp_path):
    path = os.environ.get('SIFTED_TEST_INVESTIGATION_IMAGE')
    if not path:
        pytest.skip('Set SIFTED_TEST_INVESTIGATION_IMAGE to the documented Citadel DC01 capture.')
    source = Path(path).resolve()
    symbols = Settings().volatility_symbols
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'case.db'),
                      'SIFTED_INPUT_ROOTS': [str(source.parent)], 'SIFTED_OUTPUT_ROOTS': [str(tmp_path)],
                      'SIFTED_SYMBOL_ROOTS': [symbols]})
    client, settings = app.test_client(), app.config['SETTINGS']
    repo = Repository(app.config['DATABASE_PATH'])
    case, key = register(client, repo, source)
    evidence = repo.case(case)['artifacts'][0]
    assert evidence['hash'] == '8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62'
    assert evidence['profile']['kind'] == 'memory'
    actions = view(client, case, key, tab='investigate', memory_question='indicators')['memory']['investigations']
    action = next(action for action in actions if action['id'] == 'rules')
    data = action['payload']
    data.update(output_path=str(tmp_path / 'managed YARA results'), symbol_path=symbols, offline=True)
    data['plugin_options'][action['plugin']].update({f['name']: f['default'] for f in action['fields']})
    plan, _, _ = compile_plan('volatility', data, settings, repo, preview=True)
    assert not plan.auxiliary_paths
    assert not any(DEFAULT_RULES.is_relative_to(root) for root in settings.input_roots)
    response = client.post('/api/volatility/run', json=data)
    assert response.status_code == 202, response.json
    Worker(repo, settings).run_once()
    run = repo.run(response.json['run_id'])
    assert run['status'] == 'success', run.get('error')
    assert run['input_sha256'] == evidence['hash']
    saved = Path(run['output_path']) / '_sifted/yara'
    assert (saved / 'memory.yar').read_bytes() == DEFAULT_RULES.read_bytes()
    library = run['plan']['parameters']['yara_libraries'][action['plugin']]
    assert hashlib.sha256((saved / 'memory.yar').read_bytes()).hexdigest() == library['sha256']
    assert len(list((saved / 'licenses').iterdir())) == 3
    assert client.get('/view-file', query_string={'path': str(saved / 'manifest.json')}).status_code == 200
    native, output = paste(plan, settings)
    assert native.returncode == 0, native.stdout + native.stderr
    report = Path(run['output_path']) / run['plugin_results'][0]['file']
    def rows(path):
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    managed_rows = rows(report)
    assert managed_rows == rows(output / (action['plugin'] + '.jsonl'))
    assert run['plugin_results'][0]['row_count'] == len(managed_rows)
    print(f"Citadel: managed scan and pasted CLI agree; {len(managed_rows)} matches, {library['rule_count']} rules; case {case}, evidence {key}")
