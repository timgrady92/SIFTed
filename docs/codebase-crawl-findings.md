# Codebase Crawl Findings

## System Map (Brief)
- Flask app in `app.py` drives all routes, tool orchestration, and file I/O; `wsgi.py` is the WSGI entrypoint.
- State is stored in JSON files under `data/` (`cases.json`, `runs.json`); runtime run events use in-memory `RUN_STATE` with background threads.
- External forensic tools are executed via `subprocess` with outputs stored under output roots; UI is static HTML + JS in `templates/` and `static/`.

## Findings

### Critical
- None found.

### High
- None found.

### Medium
- **Run record updates were not atomic, risking lost run status/metadata in concurrent runs.** Evidence: `app.py` functions `create_run_record` and `update_run_status` previously performed read-modify-write with separate locks, allowing interleaving across threads. **Fixed.**
- **Post-process failures could still report exit code 0, masking errors in the UI.** Evidence: `app.py` `start_generic_run` emitted error status but left `exit_code` unchanged on post-process exceptions, while the client uses `exit_code` for success/failure messaging. **Fixed.**

### Low
- **Filetype command preview was inaccurate (missing `-b`, incorrect `find -exec` syntax).** Evidence: `app.py` `run_filetype` and `static/filetype.js` preview logic. **Fixed.**
- **ExifTool output format was not validated; invalid formats produced misleading output filenames.** Evidence: `app.py` `run_exiftool` accepted arbitrary `output_format`. **Fixed.**

## Actions Taken
- Made run record updates atomic with re-entrant locking in `app.py` to prevent concurrent write loss.
- Ensured post-process failures force a non-zero exit code in `app.py` to align status + UI messaging.
- Added an explicit filetype command preview helper in `app.py` and corrected preview formatting in `static/filetype.js`.
- Validated ExifTool output format input in `app.py`.
- Added targeted tests for these behaviors in `tests/test_app.py`.

## Recommended Follow-ups (Not Implemented)
- **Validate Volatility plugin names against the loaded catalog** to prevent arbitrary option injection. Evidence: `app.py` `run_volatility` accepts user-provided plugin strings. Reason: needs product decision on whether free-form plugins are supported.
- **Avoid re-parsing full CSV/JSON files on every table page request** by adding streaming or caching for `api/table-rows`. Evidence: `app.py` `api_table_rows` uses full-file parsing each call. Reason: would require broader refactor and caching strategy.
- **Align case creation validation with `SIFTED_INPUT_ROOTS`.** Evidence: `app.py` `cases` route hashes any file path without input root enforcement. Reason: behavior change should be confirmed.

## How I Validated
- `venv/bin/python -m unittest discover -s tests`
