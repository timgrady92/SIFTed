# Runtime design

`app.py` creates Flask instances and registers the web and execution blueprints. Importing it does not create databases or launch workers. `config.py` is the shared configuration boundary for both processes; `context.py` creates an application-scoped repository lazily. `web.py`, `presentation.py`, and `viewers.py` own page behavior, curated content, and bounded result parsing.

## Execution contract

A `ToolAdapter` declares accepted parameter names and source kinds and implements `build()` in `adapters.py`. It returns a `Plan` containing argument lists, output redirections, deadlines, expected files, and configuration snapshots. Register a new adapter in `ADAPTERS`, add its parameter controls and payload builder, and test it through `Worker`. Avoid independent command construction in the frontend or new subprocess runners in route handlers.

Unknown parameters are rejected, so a misspelled option cannot silently fall back to a default. Clients cannot submit shell commands. The worker uses `shell=False`, closed stdin, a stable C locale, and a new process group for each step. Standard output destined for a result file stays separate from diagnostics. All workflow requests use `source_path`; there is no alternate image-path request field. Streaming pipe reads bound memory consumption; failures retain diagnostic tails and partial output. A zero exit code without required output is a failure.

The worker hashes input evidence before execution and verifies its recorded identity after execution. Directory membership and file identities are snapshotted when enqueued and revalidated before execution. Membership snapshots include all descendants, including those a nonrecursive identification run may not process. Directory evidence must contain regular files and directories only. Hashing large inputs costs time and falls within the execution deadline.

## Persistence and recovery

`storage.py` owns transactions and the versioned schema (`PRAGMA user_version`). Schema version 1 creates a fresh database; future schema changes must add explicit migrations. A newer database version is rejected. SQLite runs in WAL mode with foreign keys and short-lived connections. Case mutations serialize, claims are atomic, output destinations are unique, and terminal state plus manifest plus completion event commit together.

One worker per database is enforced by a Linux file lock. It renews a heartbeat while running. HTTP processes may be restarted or multiplied independently. Jobs waiting in SQLite remain queued. At startup, the worker marks formerly running jobs interrupted, kills a recorded orphan process group only when its Linux process start identity matches, and indexes any staged or already-published results. Recovery does not automatically rerun tools.

Attempts live beside their destination under `.sifted-staging/<run_id>`, keeping publication on the same filesystem. Successful and failed results are hashed and published by directory rename. Logs are saved beside the destination as `<output_path>.log`. A crash between rename and database commit is recovered by reindexing the destination. If publication cannot finish, the workspace path is recorded and preserved for inspection. Retry creates a new job and output directory; it never overwrites the old attempt.

Back up the durable database using SQLite's backup API or a tool that understands WAL. Copying only the main database while services write may omit committed changes. Preserve the output directories and adjacent logs with the database. The `.tables.sqlite3` cache can be discarded and rebuilt.

## Resource and deployment boundaries

The worker is serial by design. Subprocess output is capped while streaming, and attempt disk use is checked periodically; this is a monitored budget, not a filesystem quota. Tools can write between checks. Artifact hashing and publication follow execution and can extend elapsed time beyond the execution deadline. Process groups are terminated on cancellation, shutdown, timeout, and step completion. An interrupted attempt retains its partial artifacts and does not represent complete forensic results.

Run SIFTed with an account permitted to read evidence and create output directories. Keep database, lock, and output storage on local filesystems. WSGI workers only serve HTTP; supervise the separate worker using the same configuration. The local launcher runs both and stops serving if its worker exits. There is no authentication or multi-user isolation layer; bind to localhost for the intended analyst workstation usage.

## Validation boundaries

`test_app.py` checks the HTTP contract and case workflows. `test_runtime.py` exercises real subprocesses using deterministic fake forensic tools, transaction races, worker process ownership, restart recovery, and manifest hashes. `test_live_tools.py` runs installed forensic tools through the same queue and worker. `test_browser.py` optionally checks Chromium rendering, previews, submission, and completion with the event stream unavailable.

The live smoke suite establishes CLI integration for the installed workstation and synthetic inputs. It does not establish parser accuracy across forensic artifact versions. Adding a parser option requires a meaningful adapter/worker test and, when feasible, a small documented fixture with known expected results.
