# Native SIFT CLI examples

The **Run it in a SIFT terminal** panel teaches how to use the installed forensic tool directly. **Copy CLI commands** copies the entire example; **Save .sh** saves the same text for `bash forensic-commands.sh`. The controls are disabled until the evidence path and options are valid. Clipboard copying also works over ordinary HTTP.

Examples use the selected evidence and relevant native options. Their small Bash preparation block names the evidence and creates a fresh results folder beside the chosen output path, or under `~/forensic-results` when no output is selected. Parentheses keep shell variables and `set -e` local to the example. Repeated pastes preserve existing results. Paths and literal rules are quoted, including spaces, apostrophes, dollar signs, backticks, Unicode and newlines where the native tool supports them.

The commands use installed executable names, native reports and shell redirection. They contain no worker timeouts, audit manifests, app validators, embedded Python executors, installation snapshots or SIFTed job directories. Explanations beside the commands describe the flags and how to interpret their output. A saved example requires the forensic tool and its installed resources, independently of SIFTed.

## Tool-specific preparation

- Foremost uses `-t` with its built-in parsers and the workstation's default configuration. Scalpel needs active header/footer rules: its example creates a short local configuration containing the selected signatures. Both write to a new `carved/` directory; review the native audit and recovered files.
- Bulk Extractor writes its native feature files into `features/`. Plaso demonstrates extraction with `log2timeline.py`, followed by CSV export with `psort.py`.
- Volatility adds a writable symbol directory under `~/.local/share/volatility3/symbols`, alongside any explicitly selected symbol directory. This is necessary on the tested vanilla SIFT workstation because its system symbol directories are read-only to the analyst account. Global options precede the exact installed plugin name; selected plugin options follow it. Each plugin gets a report and a separate directory for any extracted files. The example does not save SIFTed's execution configuration.
- Zimmerman examples invoke the installed .NET DLL with `dotnet`, select a file with `-f` or a directory with `-d`, and export with `--csv`. RECmd references the installed batch profile; EvtxECmd references its installed maps. Registry parsers operate on an ordinary writable evidence copy with adjacent transaction logs. On Linux, the examples give copied logs the uppercase `.LOG1`/`.LOG2` names required by the parsers, preserving the originals. Native diagnostics remain visible in the terminal; review them even when the parser exits zero.
- SQLite examples teach `sqlite3`, rather than reproducing SIFTed's map executor. They copy the database with its available WAL/SHM/journal sidecars, list tables, save the schema, and export the first SQL query from each selected profile using `-readonly -header -csv`. Analysts should check those queries against the schema before reusing them. Automatic map matching, deduplication and configured blob extraction remain app features. The native Linux SQLECmd installation on the tested workstation lacks its required SQLite library.
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

The revised examples passed **52 independent native CLI checks** on the connected SIFT workstation, including collected-directory parsing, lowercase registry log captures, SQLite WAL inspection and the real Windows memory image. The local full suite passed **330 checks**, including **eight Chromium checks**, with 146 skips for unavailable native tools or fixtures. Follow-up checks of the final copy preparation passed all 58 affected local HTTP, integration and CLI checks.
