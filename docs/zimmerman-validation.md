# Zimmerman artifact parsing

All eleven catalog entries use the shared durable queue, input verification, process groups, budgets, staging, provenance, publication and paged viewers. The dedicated adapter owns each parser's input signatures, command options, installed version and export schema. The old generic CSV assumptions, shell-wrapper execution fallback, catalog toggle and synthetic smoke assertions have been removed.

## Native SIFT installation

Validation used the connected SIFT workstation's existing `/opt/zimmermantools` installation and `/usr/bin/dotnet` runtime 9.0.20. No native tools, global packages or existing services were changed.

| Parser | Installed version | Verified result |
| --- | --- | --- |
| AmcacheParser | 1.5.2.0 | 166 rows across native exports, including the known 7-Zip executable SHA-1 |
| AppCompatCacheParser | 1.5.1.0 | 1,024 ShimCache entries from the pinned SYSTEM hive |
| LECmd | 1.5.1.0 | Exact Unicode target from a generated shortcut; duplicate names retained separately |
| JLECmd | 1.5.1.0 | Automatic and custom Jump List exports, embedded shortcut fields and directory entries |
| SBECmd | 2.1.0.0 | 5,010 ShellBag rows from the pinned UsrClass hive |
| RBCmd | 1.6.1.0 | Exact Unicode path, 1,024-byte size and 2024-01-01 deletion time in both $I formats |
| RecentFileCacheParser | 1.5.1.0 | Exact Unicode path from a generated RecentFileCache record |
| EvtxECmd | 1.5.2.0 | 5,009 events; known event ID, timestamp, channel and installed map enrichment |
| MFTECmd | 1.3.0.0 | Known $MFT record extracted by native `icat` from a generated NTFS image |
| RECmd | 2.1.0.0 | 4,157 ASEP rows; genuine transaction-log replay and plugin tables; completed empty batch |
| SQLECmd maps | SIFTed executor 1 | Installed Firefox map returns an independently known form-history record and UTC time |

Discovery probes actual assemblies with `-h`, checks the required command interface and parser resources, and records version and executable hashes. Queued runs reject changed installations. `SIFTED_BINARIES` can provide explicit native executable prefixes; ambiguous assemblies require an explicit prefix. SIFT's shell wrappers are not execution paths. `SIFTED_EZ_ROOT` defaults to `/opt/zimmermantools`.

Directory runs select compatible artifacts and execute each input in a separate scope. Identically named hives or shortcuts cannot overwrite each other's exports. All original CSVs are retained, including Amcache suffixes, automatic/custom Jump List tables and RECmd plugin tables. Every CSV is parsed completely with its applicable schema and consistent row widths. Diagnostics are captured separately on stdout and stderr. Native parsers sometimes return zero despite errors; error diagnostics and nonzero EVTX record-error summaries fail the run. Mixed input failures retain valid tables for inspection, and every artifact from the overall failed run remains incomplete.

JLECmd's verbose custom-list reporting incorrectly labels the source filename as an error ([upstream implementation](https://github.com/EricZimmerman/JLECmd/blob/master/JLECmd/Program.cs)). SIFTed uses its native quiet switch while preserving debug diagnostics and actual parse errors. It does not whitelist error messages.

Registry workflows operate on verified private copies of hives and selected transaction logs. Dirty hives require logs unless the analyst explicitly chooses to ignore them; that choice is recorded and displayed. Lowercase captured log names are normalized within the working directory for native Linux replay. Evidence originals remain unchanged and are rechecked after execution and export validation. RECmd's selected installed batch, EvtxECmd's maps and SQLite maps are frozen in the plan and retained under `_sifted/`. A tool cannot alter the retained configuration or replace managed provenance unnoticed.

Native CSV source paths refer to private captures when staging is needed. The saved plan maps these paths to original evidence. Native source creation/modification/access timestamps describe host files and cannot establish original Windows filesystem times. Native RECmd plugin paths may contain its export timestamp and working directory; the retained tables are linked independently from analysis. Counts include all exports and can describe overlapping artifacts.

## SQLite maps on Linux

The workstation's SQLECmd 1.1.0.0 advertises a working help interface but cannot execute a database query: it reports a missing `SQLite.Interop.dll` and exits zero. SIFTed therefore supplies an explicitly named **SIFTed SQLite maps** executor using Python's SQLite engine and Zimmerman's installed `.smap` profiles. This is the app's implementation, not a claim to execute native SQLECmd. The inspected installation provides 92 valid profiles; invalid maps, if present, are reported and unavailable.

The engine evaluates each map's identification query before its data queries. Default selection uses the original database filename; explicit map selection handles renamed evidence. Queries are streamed to CSV without losing 64-bit integer precision. Configured blobs are extracted byte-for-byte under unique, safe filenames, honoring optional name and extension fields. Each outcome records source, map ID, query, row count and error. Identification mismatches and matched zero-row tables are explicit outcomes. Any query failure fails the overall job while retaining successful query tables and incomplete captures.

SQLite connections use read-only URI mode, query-only mode and an authorizer that denies writes, attachment, configuration pragmas, extension loading and external-file functions. The read-only `data_version` pragma is permitted for existing FTS5 indexes; FTS3, FTS4 and FTS5 queries are exercised. Private captures include WAL, SHM and rollback journals. A fixed SQLite read first recovers any captured hot rollback journal on a separate private, query-only connection; map SQL then uses a read-only connection. The summary records main-file hashes before and after this preparation, and evidence originals remain unchanged. Deduplication defaults off and never collapses databases with transaction sidecars based only on their main-file hash. SQLite `localtime` expressions resolve to UTC in the managed subprocess, and this choice is recorded in analysis. Individual query deadlines, worker cancellation and attempt budgets remain enforced. Runtime setup installs PyYAML alongside the existing dependencies in the app's private virtual environment.

## Reproduce the checks

The native tests never download evidence. Small shortcuts, custom lists, Recycle Bin records and RecentFileCache records are generated with independently specified expected values. Public hives, logs, events and automatic lists remain outside the repository. Download the pinned upstream corpus from the repository root:

```python
import hashlib
import lzma
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path("tests").resolve()))
from zimmerman_samples import PUBLIC_FIXTURES

root = Path("/tmp/sifted-zimmerman-fixtures")
root.mkdir(exist_ok=True)
plaso = "0f122c3878bdac3ff716b56f23988885675fea28"
registry = "1b0b3c414569debb5ffcc629de28e3ff27145a42"
jump = "e87bacd4869cbe0633c16ad11d3d26c9f39d0a2b"
regipy = "bf1239d9bbc5ee9331bdc849ff11d2c42331f737"
files = {
    "Amcache.hve": ("log2timeline/plaso", plaso, "test_data/winreg/win10-Amcache.hve"),
    "System.evtx": ("log2timeline/plaso", plaso, "test_data/evtx/System.evtx"),
    "SYSTEM": ("EricZimmerman/Registry", registry, "Registry.Test/Hives/SYSTEM"),
    "NTUSER.DAT": ("EricZimmerman/Registry", registry, "Registry.Test/Hives/NTUSER.DAT"),
    "UsrClass.dat": ("EricZimmerman/Registry", registry, "Registry.Test/Hives/UsrClass-win7.dat"),
    "automatic.automaticDestinations-ms": ("EricZimmerman/JumpList", jump, "JumpList.Test/TestFiles/Win10/5f7b5f1e01b83767.automaticDestinations-ms"),
    "f01b4d95cf55d32a.automaticDestinations-ms": ("EricZimmerman/JumpList", jump, "JumpList.Test/TestFiles/Win10/f01b4d95cf55d32a.automaticDestinations-ms"),
    "replay-NTUSER.DAT": ("mkorman90/regipy", regipy, "regipy_tests/data/transactions_NTUSER.DAT.xz"),
    "replay-NTUSER.DAT.log1": ("mkorman90/regipy", regipy, "regipy_tests/data/transactions_ntuser.dat.log1.xz"),
    "replay-NTUSER.DAT.log2": ("mkorman90/regipy", regipy, "regipy_tests/data/transactions_ntuser.dat.log2.xz"),
}
for name, (repo, commit, path) in files.items():
    data = urllib.request.urlopen(f"https://raw.githubusercontent.com/{repo}/{commit}/{path}").read()
    if path.endswith(".xz"):
        data = lzma.decompress(data)
    assert hashlib.sha256(data).hexdigest() == PUBLIC_FIXTURES[name], name
    (root / name).write_bytes(data)
```

```sh
SIFTED_TEST_ZIMMERMAN_FIXTURES=/tmp/sifted-zimmerman-fixtures \
  .venv/bin/python -m pytest -q tests/test_zimmerman.py tests/test_sqlite_maps.py \
  tests/test_live_zimmerman.py tests/test_live_disk_tools.py
python -m pytest -q tests/test_browser.py -k zimmerman
```

Native checks compare managed CSV records against an independent direct invocation with the persisted arguments/configuration. Comparisons normalize generated workspace paths, RECmd export-directory timestamps and host source timestamps only. Tests also cover corrupt inputs, native cancellation and timeouts, sidecar drift, immutable configuration, partial results, genuine registry replay, SQLite WAL and genuine hot-journal evidence, full-text indexes, exact blob contents, unsafe SQL and query deadlines. Chromium exercises parser-specific options, preview/submission, completion through polling and structured results. Separate Chromium checks exercised the actual supervised `./sifted` deployment on SIFT through an SSH tunnel.

Final validation passed 284 local tests, including six Chromium tests; 109 optional native-tool checks were skipped locally. The final affected suite passed 220 tests on the SIFT workstation, covering Zimmerman, SQLite maps, shared runtime, application, viewers, launcher and integrated disk workflows. The broader SIFT regression passed 375 tests before the final Zimmerman refinements, with one browser-module skip. Ruff's undefined/unused-code checks, JavaScript syntax validation and `git diff --check` also passed. Temporary deployment and tunnel processes were stopped after validation; the workstation's existing SIFTed service remained running.

These checks establish integration and known results for this installed workstation and corpus. They do not certify every Windows artifact version, every installed SQLite query against every application schema, deleted-key recovery completeness or exhaustive absence of evidence. A parser's installed status reflects its command interface and required resources; evidence-specific failures remain visible run errors.
