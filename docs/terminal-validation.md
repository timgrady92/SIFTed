# Native SIFT CLI examples

The **Run it in a SIFT terminal** panel teaches how to use the installed forensic tool directly. **Copy CLI commands** copies the entire example; **Save .sh** saves the same text for `bash forensic-commands.sh`. The controls are disabled until the evidence path and options are valid. Clipboard copying also works over ordinary HTTP.

Examples show the selected absolute evidence path directly in the native command:

```bash
mmls -B /cases/nps-2009-canon2-gen6.E01 > mmls.txt
```

Run commands from a working results directory. Reports use the filenames shown in the current directory, separately from the app's output selection. Change those names to keep previous results. There are no shell variables, environment exports, subshells, strict-mode settings, temporary-folder generators or result-printing scaffolds. Literal paths and rules are quoted where needed, including spaces, apostrophes, dollar signs, backticks, Unicode and supported newlines.

The commands use installed executable names, native reports and shell redirection. They contain no worker timeouts, audit manifests, app validators, embedded Python executors, installation snapshots or SIFTed job directories. Explanations beside the commands describe the flags and how to interpret their output. A saved example requires the forensic tool and its installed resources, independently of SIFTed.

## Tool-specific preparation

- Foremost uses `-t` with its built-in parsers and the workstation's default configuration. Scalpel needs active header/footer rules: its example creates a short local configuration containing the selected signatures. They write to `foremost-carved/` or `scalpel-carved/`; review the native audit and recovered files.
- Bulk Extractor writes its native feature files into `bulk-features/`. Plaso demonstrates extraction with `log2timeline.py`, followed by CSV export with `psort.py`.
- Volatility adds a writable symbol directory under `~/.local/share/volatility3/symbols`, alongside any explicitly selected symbol directory. This is necessary on the tested vanilla SIFT workstation because its system symbol directories are read-only to the analyst account. Global options precede the exact installed plugin name; selected plugin options follow it. Each plugin writes a named report such as `windows.pslist.PsList.jsonl`; native extracted files go into the current working directory. The example does not save SIFTed's execution configuration.
- Zimmerman examples invoke the installed .NET DLL with `dotnet`, select a file with `-f` or a directory with `-d`, and export with `--csv`. RECmd references the installed batch profile; EvtxECmd references its installed maps. Registry parsers read the original hive directly when no filename preparation is necessary. On Linux, lowercase transaction logs need uppercase `.LOG1`/`.LOG2` filenames: those examples prepare writable copies of the selected hives and logs under the analyst's home directory, preserving the originals. Preparation creates a fresh copy directory and chains the commands with `&&`, so a failed preparation step stops the example. Parser CSV directories have simple names such as `recmd-csv/`. Native diagnostics remain visible in the terminal; review them even when the parser exits zero.
- SQLite examples teach `sqlite3`, rather than reproducing SIFTed's map executor. They list tables, save the schema, and pass the first SQL query from each selected profile as a quoted CLI argument using `-readonly -header -csv`. A database with WAL/SHM/journal sidecars is copied with those sidecars before inspection; a database without sidecars is inspected directly. No time zone is exported: SQLite `localtime` expressions use the workstation's time zone. Analysts should check those queries against the schema before reusing them. Automatic map matching, deduplication and configured blob extraction remain app features. The native Linux SQLECmd installation on the tested workstation lacks its required SQLite library.
- File identification uses native `file` output and `find -exec` for directory scope. MIME reports retain filenames so analysts can compare content types with extensions. The app's mismatch filtering and CSV formatting are not emulated.
- Sleuth Kit examples retain the selected geometry, metadata addresses and binary redirection. `-o` is a sector offset; inode and block addresses are filesystem-relative. `blkcalc -d` includes a native `blkls -A -l` allocation listing because index conventions vary between builds.
- Examination examples use `head`, `xxd`, `pdfinfo` or `pdftotext` directly, with the selected byte or page limits.

## Validation

Tests execute the exact displayed text through a separate Bash process with an empty `PYTHONPATH`. No web server or worker executes the commands. Known inputs establish native behavior: strings and metadata, disk geometry and extracted bytes, carving signatures, SQLite queries and WAL contents, registry log replay, native parser records and Volatility process enumeration. App-only result schemas and validation summaries are deliberately absent from these checks.

```bash
.venv/bin/python -m pytest -q tests/test_terminal.py tests/test_live_terminal.py
.venv/bin/python -m pytest -q tests/test_browser.py
```

For the installed SIFT tools and optional public fixtures:

```bash
SIFTED_TEST_ZIMMERMAN_FIXTURES=/tmp/sifted-zimmerman-review/sifted-zimmerman-fixtures \
SIFTED_TEST_MEMORY_IMAGE=/tmp/sifted-volatility-review/windows.img \
  .venv/bin/python -m pytest -q tests/test_terminal.py tests/test_live_terminal.py
```

Fixtures must already be available; the tests never download tools or evidence. See [Zimmerman validation](zimmerman-validation.md) and [Volatility validation](volatility-validation.md) for their provenance. Browser checks exercise complete copy/save text, invalid-path disabling, selected options and the existing app execution flow. The backend execution record remains an audit of the app's work, distinct from these educational commands.

The simplified examples passed **53 CLI checks** on the connected SIFT workstation, including real Windows memory analysis and process extraction. The native CLI and affected worker/parser regression passed **110 checks**. The full local suite passed **331 checks**, including **eight Chromium checks**, with 146 skips for unavailable tools or fixtures. Tests verify that the examples contain no shell variable assignments, environment exports or execution wrappers.
