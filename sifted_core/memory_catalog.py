"""Analytical questions over native plugins; execution stays in tool adapters.

See docs/memory-investigation-research.md for methodology and source references.
Canonical plugin names and typed options are checked against the installation.
"""
from .yara_rules import DEFAULT_RULES


def action(id, label, plugin, *, pid=None, options=None, group='essential', note='', fields=(), tool='volatility', min_windows=None):
    return dict(id=id, label=label, plugin=plugin, pid=pid, options=options or {}, group=group,
                note=note, fields=list(fields), tool=tool, min_windows=min_windows)


RULES = {'name': 'yara_file', 'label': 'YARA rules file', 'type': 'text',
         'native_type': 'file', 'default': str(DEFAULT_RULES), 'required': True,
         'description': 'Bundled memory indicators · Google, Mandiant, ESET. Replace the path to use your own rules.',
         'placeholder': '/cases/rules/investigation.yar'}
HIVE = {'name': 'filter', 'label': 'Registry hive', 'type': 'select', 'native_type': 'string',
        'default': '', 'required': True,
        'choices_from': {'plugin': 'windows.registry.hivelist.HiveList', 'column': 'FileFullPath'}}
QUESTIONS = {
    'network': ('Network activity', 'Which processes communicated, and with whom?',
                'Compare remote endpoints, ports, state and process ownership with the incident timeline. A socket record does not prove a completed connection; recovered objects may be stale.'),
    'injection': ('Code injection', 'Do executable regions and loaded modules agree?',
                  'Correlate region protections, mapped paths, loader lists and process context. JIT runtimes and security software can resemble injection. An empty scan does not establish that the image is clean.'),
    'persistence': ('Services and registry', 'What could explain execution or persistence?',
                    'Review service paths, start modes and associated registry hives. Corroborate with disk registry and event logs; a configured service does not prove it ran.'),
    'kernel': ('Kernel integrity', 'Do kernel lists and scans tell the same story?',
               'Compare module paths and address ranges, then inspect driver dispatch or system-call ownership. Unloaded remnants, acquisition gaps and security products can explain differences.'),
    'indicators': ('Indicators and strings', 'Can known indicators narrow the investigation?',
                   'Use reviewed YARA rules and strings to find leads. Image byte offsets are not process virtual addresses. A string, URL or rule match alone does not establish execution or communication.'),
}

PROFILES = {
    'windows': {
        'label': 'Windows', 'identify': 'windows.info.Info', 'inventory': 'windows.pslist.PsList',
        'checks': [('Process tree', 'windows.pstree.PsTree'), ('Scan for process remnants', 'windows.psscan.PsScan')],
        'process': [
            action('command', 'Read command line', 'windows.cmdline.CmdLine', pid='pid'),
            action('modules', 'Inspect loaded modules', 'windows.dlllist.DllList', pid='pid'),
            action('extract', 'Extract executable', 'windows.pslist.PsList', pid='pid', options={'dump': True}),
            action('handles', 'Inspect open objects', 'windows.handles.Handles', pid='pid', group='Process context', note='Correlate file, registry, process and mutex handles with the process purpose.'),
            action('environment', 'Read environment', 'windows.envars.Envars', pid='pid', group='Process context'),
            action('identity', 'Inspect security identifiers', 'windows.getsids.GetSIDs', pid='pid', group='Process context'),
            action('privileges', 'Inspect token privileges', 'windows.privileges.Privs', pid='pid', group='Process context', note='A privilege being present is different from it being enabled or used.'),
            action('injection', 'Inspect potential injection', 'windows.malware.malfind.Malfind', pid='pid', group='Injection and mappings'),
            action('loader', 'Compare loader lists', 'windows.malware.ldrmodules.LdrModules', pid='pid', group='Injection and mappings'),
            action('regions', 'Inspect virtual memory regions', 'windows.vadinfo.VadInfo', pid='pid', group='Injection and mappings'),
            action('capture_regions', 'Extract potential injection regions', 'windows.malware.malfind.Malfind', pid='pid', options={'dump': True}, group='Capture memory', note='Review the region report before interpreting extracted bytes as malicious code.'),
            action('capture_memory', 'Extract process memory', 'windows.memmap.Memmap', pid='pid', group='Capture memory', options={'dump': True}, note='The accompanying map relates virtual addresses to offsets in the dump; these address spaces are not interchangeable.'),
            action('rules', 'Scan process with YARA rules', 'windows.vadyarascan.VadYaraScan', pid='pid', group='Known indicators', fields=[RULES]),
        ],
        'investigations': [
            action('connections', 'Enumerate network objects', 'windows.netstat.NetStat', group='network', min_windows=6),
            action('connection_scan', 'Scan for network remnants', 'windows.netscan.NetScan', group='network', min_windows=6),
            action('injection_scan', 'Inspect potential injection', 'windows.malware.malfind.Malfind', group='injection'),
            action('process_views', 'Compare process enumeration methods', 'windows.malware.psxview.PsXView', group='injection'),
            action('services', 'Inspect services', 'windows.svcscan.SvcScan', group='persistence'),
            action('hives', 'Locate registry hives', 'windows.registry.hivelist.HiveList', group='persistence'),
            action('capture_hives', 'Extract a registry hive', 'windows.registry.hivelist.HiveList', group='persistence', options={'dump': True}, fields=[HIVE], note='Choose a hive from the recorded list, then examine it with the shared registry tools. Missing pages may prevent or limit recovery.'),
            action('modules', 'List kernel modules', 'windows.modules.Modules', group='kernel'),
            action('module_scan', 'Scan for kernel module remnants', 'windows.modscan.ModScan', group='kernel'),
            action('dispatch', 'Inspect driver dispatch tables', 'windows.driverirp.DriverIrp', group='kernel'),
            action('syscalls', 'Inspect system-call ownership', 'windows.ssdt.SSDT', group='kernel'),
            action('rules', 'Scan mapped memory with YARA rules', 'windows.vadyarascan.VadYaraScan', group='indicators', fields=[RULES]),
        ]},
    'linux': {
        'label': 'Linux', 'identify': 'banners.Banners', 'inventory': 'linux.pslist.PsList',
        'checks': [('Process tree', 'linux.pstree.PsTree')],
        'process': [
            action('command', 'Read command line', 'linux.psaux.PsAux', pid='pid'),
            action('modules', 'Inspect loaded libraries', 'linux.library_list.LibraryList', pid='pids'),
            action('extract', 'Extract executable', 'linux.pslist.PsList', pid='pid', options={'dump': True}),
            action('files', 'Inspect open files', 'linux.lsof.Lsof', pid='pid', group='Process context'),
            action('environment', 'Read environment', 'linux.envars.Envars', pid='pid', group='Process context'),
            action('shell', 'Recover shell history', 'linux.bash.Bash', pid='pid', group='Process context', note='Recovered shell history may be incomplete and is not proof each command succeeded.'),
            action('sockets', 'Inspect process sockets', 'linux.sockstat.Sockstat', pid='pids', group='Process context'),
            action('injection', 'Inspect potential injection', 'linux.malware.malfind.Malfind', pid='pid', group='Injection and mappings'),
            action('rules', 'Scan process with YARA rules', 'linux.vmayarascan.VmaYaraScan', pid='pid', group='Known indicators', fields=[RULES]),
        ],
        'investigations': [
            action('connections', 'Enumerate sockets', 'linux.sockstat.Sockstat', group='network'),
            action('interfaces', 'Inspect network addresses', 'linux.ip.Addr', group='network'),
            action('injection_scan', 'Inspect potential injection', 'linux.malware.malfind.Malfind', group='injection'),
            action('credentials', 'Compare process credentials', 'linux.malware.check_creds.Check_creds', group='injection'),
            action('modules', 'List kernel modules', 'linux.lsmod.Lsmod', group='kernel'),
            action('syscalls', 'Inspect system-call ownership', 'linux.malware.check_syscall.Check_syscall', group='kernel'),
            action('rules', 'Scan mapped memory with YARA rules', 'linux.vmayarascan.VmaYaraScan', group='indicators', fields=[RULES]),
        ]},
    'mac': {
        'label': 'macOS', 'identify': 'banners.Banners', 'inventory': 'mac.pslist.PsList',
        'checks': [('Process tree', 'mac.pstree.PsTree')],
        'process': [
            action('command', 'Read command line', 'mac.psaux.Psaux', pid='pid'),
            action('modules', 'Inspect memory mappings', 'mac.proc_maps.Maps', pid='pid'),
            action('files', 'Inspect open files', 'mac.lsof.Lsof', pid='pid', group='Process context'),
            action('sockets', 'Inspect process sockets', 'mac.netstat.Netstat', pid='pid', group='Process context'),
            action('shell', 'Recover shell history', 'mac.bash.Bash', pid='pid', group='Process context'),
            action('injection', 'Inspect potential injection', 'mac.malfind.Malfind', pid='pid', group='Injection and mappings'),
        ],
        'investigations': [
            action('connections', 'Enumerate sockets', 'mac.netstat.Netstat', group='network'),
            action('injection_scan', 'Inspect potential injection', 'mac.malfind.Malfind', group='injection'),
            action('modules', 'List kernel extensions', 'mac.lsmod.Lsmod', group='kernel'),
            action('syscalls', 'Inspect system-call ownership', 'mac.check_syscall.Check_syscall', group='kernel'),
            action('rules', 'Scan image bytes with YARA rules', 'yarascan.YaraScan', group='indicators', fields=[RULES]),
        ]},
}

SUPPORTING = [
    action('ascii', 'Extract ASCII strings', None, tool='strings', group='indicators', options={'encoding': 's', 'show_offsets': True}, note='Offsets refer to bytes in the selected image or extracted file.'),
    action('unicode', 'Extract UTF-16LE strings', None, tool='strings', group='indicators', options={'encoding': 'l', 'show_offsets': True}),
    action('features', 'Extract email and URL leads', None, tool='bulk-extractor', group='indicators', options={'focus_scanners': ['email']}, note='Features may come from cached or embedded data and do not establish network activity.'),
]
