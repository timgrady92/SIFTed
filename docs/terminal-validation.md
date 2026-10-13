# Native SIFT CLI examples

**Run it in a SIFT terminal** and the evidence workspace's **Run this yourself on SIFT** use the same presenter. Copy and Save .sh use the displayed analytical commands. Invalid evidence paths disable copying.

Examples show only the selected native operation and its absolute evidence path:

```bash
mmls -B /cases/nps-2009-canon2-gen6.E01
vol -q -f /cases/demo/memory/windows-xp.img -r jsonl windows.cmdline.CmdLine --pid 1812
```

Ordinary reports print to the terminal. Optional report redirection, managed symbol directories, configuration snapshots and backend verification steps are omitted. Paths and literal arguments remain shell-quoted, including spaces, apostrophes, dollar signs, backticks, Unicode and supported newlines. Examples contain no app executors, timeout wrappers, audit manifests or SIFTed job directories.

## Native requirements that remain

- Binary extraction (`icat`, `blkcat`, `blkls`) redirects recovered bytes to a file. Other Sleuth Kit commands print their result directly; `blkcalc` does not include SIFTed's additional allocation-verification command. Sector offsets, geometry and record addresses remain selected analytical inputs.
- Foremost, Scalpel and Bulk Extractor require native output directories. Scalpel also needs selected header/footer definitions, supplied as a short configuration. Plaso requires its storage file and exported timeline. Run file-producing operations in a working directory and choose fresh destinations for subsequent runs.
- Volatility uses installed symbols. The separate [onboarding guide](volatility-symbols.md) covers downloading, validating and installing them once. A deliberately selected additional symbol directory remains in the analytical command, as do offline mode and plugin options. Extracted memory files use Volatility's current-directory default.
- Zimmerman commands invoke the native .NET parser and installed resources. CSV destinations remain because those parsers produce files; app-specific report filenames, debug output, timestamp formatting and JLECmd's backend-only quiet flag are removed. Analytical options such as deleted-entry inclusion and transaction-log replay stay intact.
- Registry logs with lowercase names need uppercase `.LOG1`/`.LOG2` filenames on the tested Linux parsers. Those examples still prepare working copies so the native parser can replay the selected logs without renaming originals. SQLite databases with sidecars likewise need working copies to preserve the source WAL/SHM/journal bytes. Necessary preparation chains with `&&`; it does not reproduce worker staging or provenance.
- SQLite examples run the first SQL query from each selected profile through `sqlite3 -readonly -header -csv`, printing results. Repeated schema exports and automatic `.tables`/`.schema` commands are removed. Those native exploration commands remain described in the helper text.
- File identification uses `file` or `find -exec`. Strings, metadata, text, hex and PDF inspection print to the terminal. ClamAV uses its native scan defaults; the note calls out scan limits and return codes. An explicitly configured nondefault signature directory is retained.

The worker's managed output files and evidence provenance remain independent of CLI presentation. Standalone tools, case workflows, copied commands and saved scripts all use this shared rule.

## Validation

Tests paste the exact displayed command text into Bash with an empty `PYTHONPATH`, capture its terminal output, and inspect native files only for operations that produce files. They verify substantive results: text and metadata, disk structures, exact binary recovery, carving, registry replay, SQL/WAL rows, memory process records and extraction. They also verify preserved evidence and shell quoting. Obsolete expectations for redirected text reports were replaced.

```bash
.venv/bin/python -m pytest -q tests/test_terminal.py tests/test_live_terminal.py tests/test_symbol_setup.py
.venv/bin/python -m pytest -q tests/test_browser.py
```

Native SIFT reproduction, with the documented public fixtures already available:

```bash
SIFTED_TEST_ZIMMERMAN_FIXTURES=/tmp/sifted-zimmerman-review/sifted-zimmerman-fixtures \
SIFTED_TEST_MEMORY_IMAGE=/cases/demo/memory/windows-xp.img \
  .venv/bin/python -m pytest -q tests/test_terminal.py tests/test_live_terminal.py tests/test_symbol_setup.py
```

Follow symbol onboarding before the bare Windows CLI tests. On the connected SIFT workstation, a fresh targeted Windows symbol download and installation made the exact `windows.cmdline.CmdLine --pid 1812` example above succeed. It reports `explorer.exe` and `C:\WINDOWS\Explorer.EXE`. No system tool or Python package was installed, and the Volatility code remains administrator-owned.

Browser checks cover copy/save equality, ordinary HTTP clipboard fallback, guided and standalone examples, invalid paths, and the unobtrusive symbol guide on desktop and phone. Symbol-guide checks cover discovered paths, shell quoting and missing installations. Large offline packs and native Linux/macOS capture analysis are not exercised by these tests.
