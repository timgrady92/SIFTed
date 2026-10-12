"""Read-only native ClamAV examination with pinned signature provenance."""
import hashlib
import json
from pathlib import Path
import re

from .integrity import evidence_path
from .tool_base import OUTPUT, Plan, Step, ToolAdapter, ValidationError, executable, signature

# Signature inputs are explicit; ClamAV never chooses or downloads a new database
# during a job. Sidecar signatures and freshclam's state are not scan databases.
DATABASE_SUFFIXES = {'.cvd', '.cld', '.cud', '.ndb', '.ldb', '.hdb', '.hsb', '.mdb', '.msb', '.sdb', '.zmd', '.rmd', '.yar', '.yara', '.cbc', '.ign', '.ign2', '.fp', '.sfp', '.pdb', '.wdb', '.gdb', '.crb', '.idb'}


def databases(settings, digests=False):
    try:
        return _databases(settings, digests)
    except (OSError, ValueError) as exc:
        raise ValidationError(str(exc)) from exc


def _databases(settings, digests):
    root = Path(settings.clamav_database)
    if not root.is_dir():
        raise ValidationError('ClamAV signature directory is unavailable.')
    result = []
    for item in sorted(root.iterdir()):
        if item.suffix.lower() not in DATABASE_SUFFIXES:
            continue
        path = evidence_path(item)
        before = signature(path)
        if not Path(path).is_file():
            raise ValidationError('ClamAV databases must be regular files.')
        entry = {'path': path, 'signature': before}
        if digests:
            with open(path, 'rb') as handle:
                entry['sha256'] = hashlib.file_digest(handle, 'sha256').hexdigest()
            if signature(path) != before:
                raise ValidationError('ClamAV signatures changed while preparing the examination.')
        result.append(entry)
    if not result:
        raise ValidationError('ClamAV has no installed signature databases. Configure SIFTED_CLAMAV_DATABASE.')
    return result


class ClamAVAdapter(ToolAdapter):
    tool_id = 'clamscan'

    def build(self, payload, source, output, settings, preview=False):
        args = executable(self.tool_id, ['clamscan'], settings)
        snapshot = databases(settings, digests=True)
        if source != '<source_path>' and Path(source).stat().st_size > 512 * 1024 ** 2:
            raise ValidationError('ClamAV examination accepts files up to 512 MiB. Extract a focused memory object first.')
        scan = args + ['--stdout', '--allmatch', '--alert-exceeds-max=yes', '--max-filesize=512M', '--max-scansize=1024M']
        for entry in snapshot:
            scan += ['--database', entry['path']]
        return Plan(self.tool_id, source, output, [
            Step(args + ['--version'], 'Record ClamAV engine', OUTPUT + '/engine.txt', 30),
            Step(scan + ['--', source], 'Scan captured file', OUTPUT + '/clamscan.txt', settings.timeout_seconds, success_codes=[0, 1])],
            parameters={'database_directory': settings.clamav_database, 'database_manifest': snapshot},
            configs={'clamav-databases.json': json.dumps(snapshot, indent=2)},
            expected_files=['engine.txt', 'clamscan.txt'], postprocess='clamscan')

    def validate_execution(self, plan, settings):
        if (settings.clamav_database != plan.parameters['database_directory']
                or databases(settings) != [{k: e[k] for k in ('path', 'signature')} for e in plan.parameters['database_manifest']]):
            raise ValidationError('ClamAV signatures changed while queued; create a fresh examination.')

    def validate_completion(self, plan, settings):
        self.validate_execution(plan, settings)


def summarize(plan, output, check, step_results):
    import csv
    report = output / 'clamscan.txt'
    if report.is_symlink():
        raise ValueError('ClamAV report must be a regular file.')
    detections, scanned, infected = [], None, None
    with report.open(encoding='utf-8', errors='strict') as handle:
        for line in handle:
            check()
            text = line.rstrip('\r\n')
            if text.endswith(' FOUND') and ': ' in text:
                target, label = text.rsplit(': ', 1)
                detections.append((target, label.removesuffix(' FOUND')))
            if text.startswith('Scanned files: '):
                scanned = int(text.split(': ', 1)[1])
            if text.startswith('Infected files: '):
                infected = int(text.split(': ', 1)[1])
            if re.fullmatch(r'Total errors: [1-9]\d*', text):
                raise ValueError('ClamAV reported scan errors; review the execution log and report.')
    code = next(r['return_code'] for r in step_results if r['label'] == 'Scan captured file')
    if scanned is None or scanned < 1 or infected is None or bool(infected) != bool(detections) or (code == 1) != bool(infected):
        raise ValueError('ClamAV did not produce a consistent completed scan summary.')
    if any(label.startswith('Heuristics.Limits.Exceeded') for _, label in detections):
        raise ValueError('ClamAV reached a scan limit; the scan is incomplete. Review clamscan.txt.')
    with (output / 'detections.csv').open('x', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['File', 'Signature'])
        writer.writerows(detections)
    return {'analysis': {'table': 'detections.csv', 'scanned_files': scanned, 'signature_matches': len(detections),
                         'interpretation': 'Signature matches require corroboration; no matches do not prove a file is safe.'}}
