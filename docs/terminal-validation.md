# SIFT terminal workflow validation

The **SIFT terminal** panel supplies a complete Bash snippet for the selected evidence and options. **Copy Bash snippet** copies every line, including content outside the visible scroll area. **Save .sh** saves the same text; run the saved file with `bash sift-terminal.sh`. No executable permission is needed. The app disables both controls while options are being validated, when paths are invalid, or when evidence has not been selected. Clipboard copying also works on SIFT's ordinary HTTP deployment using the browser's copy fallback.

Each invocation creates `<chosen-output-name>.terminal.<random>/` beside the chosen output path, shortening long names to fit filesystem limits. With no chosen output it uses `~/sifted-terminal/<tool>.terminal.<random>/`. Native results go under `results/`; included configuration, helper scripts and necessary working evidence copies remain under `work/`. The terminal prints the exact result path when the child Bash shell exits. Previous results and SIFTed's selected output directory are preserved, so an unchanged snippet can be pasted repeatedly.

## What the snippets include

The renderer consumes the validated plan rather than reconstructing tool arguments in JavaScript. Shell quoting preserves spaces, apostrophes, dollar signs, backticks, Unicode and newlines in evidence filenames. Line continuations keep options and their arguments together; there are no terminal prompts, ellipses or unresolved staging placeholders to remove before copying. A child Bash shell contains strict-mode and locale settings without changing the analyst's interactive shell.

Recipes check command availability, create output parents and redirection directories, write the exact selected carving rules and parser maps with quoted heredocs, and run tools from a private working directory. Registry and SQLite workflows copy selected inputs and transaction sidecars before replay. Input SHA-256 manifests are checked again when the shell exits. Forensic commands receive `/dev/null` as stdin, keeping tools from consuming the remaining pasted script or waiting for interactive input. Per-step `timeout` commands retain results and report failures.

Flag comments explain character encodings and byte offsets, Plaso extraction versus export, Volatility global versus plugin arguments, native parser DLLs, carving profiles, and Sleuth Kit geometry. TSK offsets are sector coordinates; inode and data-unit addresses belong to the selected filesystem. `blkcalc -d` retains a separate allocation listing for establishing a zero-based unallocated-stream position when native index conventions differ.

Most workflows run the installed tool directly. File identification includes the same Python CSV reporting code used by the worker, preserving recursive scope and MIME mismatch filtering. Native Zimmerman snippets include the same diagnostic and CSV validation code used by the worker, so an exit-zero parser error cannot be reported as successful validation. SQLite maps include the existing standalone read-only executor and selected `.smap` profiles. These helpers are readable Python source inside the snippet; they import no SIFTed package and require no SIFTed installation. SQLite additionally needs Python 3.11+ and PyYAML, which are available on the tested vanilla SIFT workstation. The installed Linux SQLECmd binary cannot execute queries because its SQLite native library is missing; the snippets accurately identify the included map executor.

Independent terminal execution produces native reports, the included helpers' CSV/summary files, private captures and input manifests. SIFTed's durable jobs, case registration, published artifact manifests, carving source-range audit CSV, partition/listing interpretation CSV and other app-derived summaries remain app features. Sample-size checks in terminal snippets happen after capture; the app additionally monitors streaming output and total attempt budgets. Known results below establish repeatable integration on the tested tools and fixtures, rather than certification of every artifact format or parser algorithm.

## Reproduce

The checks run the exact rendered text through a separate Bash process with an empty `PYTHONPATH`. They never start the web app or a worker to execute a terminal workflow. Real tools, synthetic known inputs, public registry/event fixtures and the optional Windows memory image must already be available; tests never download tools or evidence.

```bash
.venv/bin/python -m pytest -q tests/test_terminal.py tests/test_live_terminal.py
.venv/bin/python -m pytest -q tests/test_browser.py
```

For the complete SIFT corpus, set the fixture paths documented in [Zimmerman validation](zimmerman-validation.md) and [Volatility validation](volatility-validation.md):

```bash
SIFTED_TEST_ZIMMERMAN_FIXTURES=/tmp/sifted-zimmerman-fixtures \
SIFTED_TEST_MEMORY_IMAGE=/tmp/sifted-memory-test/windows.img \
  .venv/bin/python -m pytest -q tests/test_terminal.py tests/test_live_terminal.py
```

Native terminal checks cover ASCII/UTF-16 strings, ExifTool CSV/JSON, MIME mismatch filtering, Bulk Extractor, Plaso, both carvers with exact recovered bytes and included rules, all nine TSK tools with independently known disk geometry and binary content, four examination tools, all eleven Zimmerman workflows, real registry transaction-log replay, installed SQLite maps, symbol-free Volatility and PID-filtered process enumeration on the public Windows image. Native registry, shellbag and EVTX checks reproduce the known row counts in the Zimmerman validation record. SQLite checks additionally preserve WAL sidecars, exact 64-bit integers and configured blob bytes and reject writes. Shell checks cover literal configuration, repeated pastes, preserved existing results, native failures, changed evidence, closed stdin and valid empty-directory reports. Browser checks cover copy/save equality, invalid-path disabling, untruncated plugin commands, parser options, queue submission and completion through polling.

The full SIFT regression passed **435 tests**, with one optional browser-module skip. After the final filename-length refinements, the affected SIFT suite passed **59 tests**, including all **48 standalone terminal checks** and the HTTP checks. The local full suite passed 303 tests with 138 optional native-tool/fixture skips; the final local terminal/HTTP/integration checks passed 59 tests. All six Chromium checks passed. A separate Chromium session against the supervised SIFT deployment verified real clipboard contents through both copy methods, script download equality, page width and absence of JavaScript errors. Its copied LECmd and SQLite snippets produced the independently known records after the temporary app was stopped. The existing workstation service remained running, and the temporary app and SSH tunnel were cleaned up.
