"""Scanner findings are successful outcomes; errors/limits stay incomplete."""
import json
from pathlib import Path
import sys

import pytest

from sifted_core.adapters import compile_plan
from sifted_core.storage import Repository
from sifted_core.tool_base import Settings, ValidationError
from sifted_core.worker import Worker
from test_runtime import enqueue


@pytest.fixture
def scanner(tmp_path):
    source = tmp_path / 'captured process.exe'; source.write_bytes(b'MZ' + b'\0' * 128)
    db = tmp_path / 'signatures'; db.mkdir(); (db / 'test.ndb').write_text('test:0:*:4d5a')
    script = tmp_path / 'scanner.py'
    script.write_text('''import sys
if '--version' in sys.argv: print('ClamAV test engine'); sys.exit(0)
print('Scanned files: 1\\nInfected files: 0')
''')
    settings = Settings(input_roots=[str(tmp_path)], output_roots=[str(tmp_path)],
                        binaries={'clamscan': [sys.executable, str(script)]}, clamav_database=str(db))
    return Repository(tmp_path / 'case.db'), settings, source, script


def submit(scanner):
    repo, settings, source, _ = scanner
    plan, case, record = compile_plan('clamscan', {'source_path': str(source), 'output_path': str(source.parent / 'output')}, settings, repo)
    return enqueue(repo, plan, record, case), plan


@pytest.mark.parametrize('outcome', ['clean', 'match', 'error', 'limit', 'missing_summary', 'queued_database_change', 'during_database_change'])
def test_scanner_outcomes_and_database_identity(scanner, outcome):
    repo, settings, source, script = scanner
    if outcome in {'match', 'limit'}:
        label = 'Known.Test.Signature' if outcome == 'match' else 'Heuristics.Limits.Exceeded.MaxFileSize'
        script.write_text("import sys\nif '--version' in sys.argv: print('ClamAV test engine'); sys.exit(0)\nprint(sys.argv[-1]+': " + label + " FOUND')\nprint('Scanned files: 1\\nInfected files: 1')\nsys.exit(1)\n")
    elif outcome == 'error':
        script.write_text("import sys\nprint('scan failure', file=sys.stderr)\nsys.exit(2)\n")
    elif outcome == 'missing_summary':
        script.write_text("print('no summary')")
    elif outcome == 'during_database_change':
        script.write_text("from pathlib import Path\nimport sys\nif '--version' in sys.argv: print('version'); sys.exit(0)\nPath(sys.argv[sys.argv.index('--database')+1]).write_text('modified')\nprint('Scanned files: 1\\nInfected files: 0')")
    run, plan = submit(scanner)
    if outcome == 'queued_database_change':
        (Path(settings.clamav_database) / 'test.ndb').write_text('changed')
    Worker(repo, settings).run_once()
    result = repo.run(run['id'])
    if outcome in {'clean', 'match'}:
        assert result['status'] == 'success', result.get('error')
        assert result['analysis']['signature_matches'] == int(outcome == 'match')
        assert result['steps'][-1]['return_code'] == int(outcome == 'match')
        manifest = json.loads((Path(plan.output_path) / '_sifted/clamav-databases.json').read_text())
        assert manifest[0]['sha256'] and manifest[0]['path'].endswith('test.ndb')
    else:
        assert result['status'] == 'error'
        assert all(not a['complete'] for a in repo.artifacts(run['id']))
    assert source.read_bytes().startswith(b'MZ')


def test_missing_symlinked_databases_and_source_limit(scanner):
    repo, settings, source, _ = scanner
    database = Path(settings.clamav_database) / 'test.ndb'
    database.unlink()
    with pytest.raises(ValidationError, match='no installed'):
        submit(scanner)
    database.symlink_to(source)
    with pytest.raises(ValidationError, match='symbolic'):
        submit(scanner)
    database.unlink()
    database.write_text('test:0:*:4d5a')
    with source.open('ab') as handle:
        handle.truncate(512 * 1024 ** 2 + 1)
    with pytest.raises(ValidationError, match='512 MiB'):
        submit(scanner)


def test_terminal_example_keeps_native_arguments_and_evidence_path(scanner):
    from test_terminal import paste
    from sifted_core.terminal import recipe
    _, settings, source, script = scanner
    script.write_text("import sys\nfrom pathlib import Path\nassert sys.argv[-2]=='--'\nassert Path(sys.argv[-1]).is_file()\nassert Path(sys.argv[sys.argv.index('--database')+1]).is_dir()\nprint('Scanned files: 1\\nInfected files: 0')\n")
    _, plan = submit(scanner)
    completed, output = paste(plan, settings)
    assert completed.returncode == 0, completed.stderr
    assert 'Scanned files: 1' in completed.stdout
    assert not (output / 'clamscan.txt').exists()
    command = recipe(plan, settings)['terminal_command']
    assert str(source) in command and '>' not in command
    assert '--max-filesize' not in command and '--stdout' not in command
