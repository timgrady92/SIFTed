"""Native profiling is bounded, content-led and part of verified intake."""
import json
from pathlib import Path
import sys
import threading
import time

import pytest

from sifted_core import evidence_assessment
from sifted_core.evidence_profile import profile
from sifted_core.worker import Worker
from test_evidence_intake import intake_runtime as intake_runtime, register, upload, put, assert_chain
from test_evidence_workspace import view


@pytest.fixture
def assessed_intake(intake_runtime, monkeypatch):
    _, _, settings, _, root = intake_runtime
    controls = root.parent / 'probe-controls.json'
    controls.write_text(json.dumps({'memory': {'status': 'matched', 'kind': 'memory', 'facts': {'os': 'windows'}},
                                   'disk': {'status': 'no_match'}}))
    runner = root.parent / 'native-runner.py'
    runner.write_text('''import json,sys,time
from pathlib import Path
value=json.loads(Path(sys.argv[1]).read_text())[sys.argv[3]]
if value.get('wait'):
 Path(sys.argv[1]+'.started').touch()
 time.sleep(30)
print(json.dumps(value))
''')
    prefix = [sys.executable, str(runner), str(controls)]
    settings.binaries['forensic-python'] = prefix
    monkeypatch.setattr(evidence_assessment, 'runtime', lambda settings: ([], prefix, ''))
    detector = root.parent / 'filetype.py'
    detector.write_text("print('application/etl')")
    settings.binaries['filetype'] = [sys.executable, str(detector)]
    strings = root.parent / 'strings.py'
    strings.write_text("print('known text')")
    settings.binaries['strings'] = [sys.executable, str(strings)]
    return intake_runtime, controls


@pytest.mark.parametrize('name', ['capture.mem', 'misleading.jpg', 'no-extension'])
@pytest.mark.parametrize('transport', ['upload', 'workstation'])
def test_native_assessment_automatically_routes_identical_bytes(assessed_intake, name, transport):
    runtime, controls = assessed_intake
    client, repo, settings, case, root = runtime
    data = b'\0' * 1024 ** 2
    if transport == 'upload':
        base = upload(runtime, [(name, data)], primary=0)
        assert put(client, base, 0, 0, data).status_code == 200
        queued = client.post(base + '/complete')
        Worker(repo, settings).run_once()
        item = repo.case(case)['artifacts'][0]
        run = repo.run(queued.json['run_id'])
    else:
        source = root / name
        source.write_bytes(data)
        item, run = register(runtime, source)
    assert run['status'] == 'success', run.get('error')
    assert item['type'] == 'memory_dump' and item['type_basis'] == 'content'
    observed = item['profile']
    assert observed['kind'] == 'memory' and observed['mime'] == 'application/etl'
    assert observed['assessment']['signature_kind'] == 'content'
    assert observed['memory']['os'] == 'windows'
    model = view(client, case, 'e:' + item['id'])
    assert model['is_memory'] and not model['acquisition']['needed']
    assert model['memory']['os'] == 'windows'
    assert all(probe['execution']['executables'] for probe in observed['assessment']['probes'])
    assert (Path(run['output_path']) / '_sifted/profiling/memory.json').is_file()
    assert_chain(repo.custody(case, item['id']))
    assert not any(e['event'] == 'classification_changed' for e in repo.custody(case, item['id'])['events'])
    # Reads, analysis and re-verification reuse supported observations of the
    # same verified bytes; they cannot silently lose the workflow if tools go away.
    controls.write_text('{}')
    assert view(client, case, 'e:' + item['id'])['is_memory']
    queued = client.post('/api/strings/run', json={'case_id': case, 'source_path': item['path']})
    Worker(repo, settings).run_once()
    assert repo.run(queued.json['run_id'])['status'] == 'success'
    queued = client.post(f"/api/case/{case}/evidence/{item['id']}/verify")
    Worker(repo, settings).run_once()
    assert repo.run(queued.json['run_id'])['status'] == 'success'
    assert repo.case(case)['artifacts'][0]['profile'] == observed


@pytest.mark.parametrize('state', ['no_match', 'unavailable', 'inconclusive'])
def test_extension_and_probe_failure_never_establish_memory(assessed_intake, state):
    runtime, controls = assessed_intake
    controls.write_text(json.dumps({'memory': {'status': state}, 'disk': {'status': 'no_match'}}))
    source = runtime[-1] / 'misleading.mem'
    source.write_bytes(b'\0' * 1024 ** 2)
    item, run = register(runtime, source)
    assert run['status'] == 'success'
    assert item['profile']['kind'] == 'content'
    assert not view(runtime[0], runtime[3], 'e:' + item['id'])['is_memory']
    assert next(p for p in item['profile']['assessment']['probes'] if p['name'] == 'memory')['status'] == state


def test_conflicting_structures_require_context(assessed_intake):
    runtime, controls = assessed_intake
    value = json.loads(controls.read_text())
    value['disk'] = {'status': 'matched', 'kind': 'disk', 'facts': {'partitions': [{'start': 1, 'length': 20}]}}
    controls.write_text(json.dumps(value))
    source = runtime[-1] / 'capture.mem'
    source.write_bytes(b'\0' * 1024 ** 2)
    item, run = register(runtime, source)
    assert run['status'] == 'success'
    assert item['profile']['assessment']['status'] == 'conflict' and item['profile']['kind'] == 'unknown'
    assert view(runtime[0], runtime[3], 'e:' + item['id'])['acquisition']['needed']


def test_recognized_file_never_needs_an_acquisition_probe(assessed_intake):
    runtime, controls = assessed_intake
    controls.write_text('{}')
    source = runtime[-1] / 'document.mem'
    source.write_bytes(b'%PDF-1.7\n' + b'\0' * 1024 ** 2)
    item, run = register(runtime, source)
    assert run['status'] == 'success' and item['profile']['kind'] == 'pdf'
    assert 'assessment' not in item['profile']


def test_profile_reads_never_launch_native_assessment(assessed_intake):
    runtime, _ = assessed_intake
    source = runtime[-1] / 'capture.mem'
    source.write_bytes(b'\0' * 1024 ** 2)
    assert profile(source, runtime[2])['kind'] == 'content'


def test_reverification_upgrades_profile_and_retries_unresolved_probes(assessed_intake):
    runtime, controls = assessed_intake
    client, repo, settings, case, root = runtime
    available = controls.read_text()
    controls.write_text(json.dumps({'memory': {'status': 'unavailable'}, 'disk': {'status': 'no_match'}}))
    source = root / 'renamed.jpg'
    source.write_bytes(b'\0' * 1024 ** 2)
    item, _ = register(runtime, source)
    baseline = item['hash']
    assert item['profile']['kind'] == 'content'
    controls.write_text(available)
    for old_version in (False, True):
        if old_version:
            def earlier_profile(case):
                profile = case['artifacts'][0]['profile']
                profile.update(version=1, kind='content', label='application/etl')
                profile.pop('assessment')
                profile.pop('memory')
            repo.mutate_case(case, earlier_profile)
        queued = client.post(f"/api/case/{case}/evidence/{item['id']}/verify")
        Worker(repo, settings).run_once()
        assert repo.run(queued.json['run_id'])['status'] == 'success'
        current = repo.case(case)['artifacts'][0]
        assert current['hash'] == baseline and current['profile']['kind'] == 'memory'
        assert current['profile']['version'] == 2
        assert current['type_basis'] == 'content'
    assert_chain(repo.custody(case, item['id']))


@pytest.mark.parametrize('result', [None, {'status': 'matched', 'kind': 'pdf', 'facts': {}}, {'status': 'matched', 'kind': 'memory'}])
def test_invalid_native_reports_do_not_become_workflow_decisions(assessed_intake, result):
    runtime, controls = assessed_intake
    controls.write_text(json.dumps({'memory': result, 'disk': {'status': 'no_match'}}))
    source = runtime[-1] / 'capture.mem'
    source.write_bytes(b'\0' * 1024 ** 2)
    item, run = register(runtime, source)
    assert run['status'] == 'success' and item['profile']['kind'] == 'content'
    assert item['profile']['assessment']['probes'][0]['status'] == 'inconclusive'


def test_native_profiling_cancellation_uses_worker_supervision(assessed_intake):
    runtime, controls = assessed_intake
    client, repo, settings, case, root = runtime
    controls.write_text(json.dumps({'memory': {'wait': True}, 'disk': {'status': 'no_match'}}))
    source = root / 'capture.mem'
    source.write_bytes(b'\0' * 1024 ** 2)
    queued = client.post(f'/api/case/{case}/artifacts', json={'path': str(source)}).json
    worker = Worker(repo, settings)
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not Path(str(controls) + '.started').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert Path(str(controls) + '.started').exists()
        response = client.post(f"/api/run/{queued['run_id']}/cancel")
        assert response.status_code == 200
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert repo.run(queued['run_id'])['status'] == 'cancelled'
        assert repo.run(queued['run_id']).get('process') is None
        assert repo.case(case)['artifacts'][0]['status'] == 'failed'
    finally:
        worker.stop.set()
        thread.join(timeout=5)
