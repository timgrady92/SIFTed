# SIFTed

> **Note**: Full disclosure, this version of the application is purely developed using a mixture of Claude Code and Codex. I would love to get this concept in front of a dedicated team of developers. The mission statement of this design is simple: allow junior DFIR analysts to meaningfully contribute on day one of the job while getting exposure to the concepts. Best case: the analyst outgrows the tool within six months.

> **Note**: Tool integration is currently in development. Workflows are being introduced slowly and methodically after rigorous testing. Existing workflows should be treated as experimental at best.

**Training wheels for forensic analysts.**

Most forensic tools assume you already know what you're doing. SIFTed assumes you're learning.

Every workflow shows how to run the analysis directly in a SIFT terminal. Every output links back to the artifacts that matter. Every guide explains not just *what* to look for, but *why* it matters and *when* to stop looking.

**We measure success by obsolescence.** An analyst who needs SIFTed indefinitely isn't learning—they're dependent. The goal is internalized knowledge, not a permanent crutch.

## How It Works

### Day One Value

Junior analysts can run complex forensic workflows immediately:

- **File carving** with Foremost and Scalpel—select file types, click run, review recovered files
- **Memory analysis** with Volatility 3—choose investigation bundles like "Malware + Evasion" or "Network Activity"
- **Bulk feature extraction**—scan disk images for emails, URLs, credentials, and other high-value indicators
- **Timeline creation** with Plaso—build CSV timelines from host artifacts
- **Artifact parsing** with Eric Zimmerman tools—extract evidence from Amcache, registry hives, Event Logs, and more

No command-line memorization required. No syntax errors. No wasted cycles on typos.

### Transparent Learning

Every action teaches:

- **Native CLI examples**: Copy or save concise commands for the tools installed on SIFT, using your selected evidence and options. Read the flag explanations and learn how to inspect artifacts independently in the terminal.
- **Integrated glossary**: Hover over forensic terms for instant definitions. Artifacts, registry keys, persistence mechanisms, Windows event codes—all searchable and contextual.
- **Investigation guides**: Hypothesis-driven playbooks that frame problems, identify evidence sources, warn about pitfalls, and define exit conditions.

The UI is explicit about what it's doing. Nothing is hidden. Nothing is magic.

Examples show the native command with the absolute evidence path, such as `mmls -B /cases/disk.E01 > mmls.txt`. Run them from a working results directory; reports use the filenames shown, which you can change for another run. There are no shell variables, environment exports or execution wrappers. Necessary tool preparation appears as ordinary commands, such as creating a writable Volatility symbol directory or defining Scalpel rules. Saved examples run with `bash forensic-commands.sh`. SQLite examples use `sqlite3` for schema inspection and SQL queries; file identification uses `file` and `find`. [CLI example validation](docs/terminal-validation.md) describes the native checks and output conventions.

### Structured Output

Results stay organized:

- Case-centric workflows keep evidence, runs, and outputs together
- Timestamped output folders prevent overwrites
- Logs capture everything for review and auditing
- CSV and JSON outputs feed into downstream analysis

Senior analysts can review junior work by examining the same artifacts and logs.

## Guides

Guides are the core of SIFTed's training philosophy. They're not documentation—they're investigation playbooks designed to build forensic intuition.

### Two Approaches

**Hypothesis-driven**: Start with a theory. *"I think a phishing email led to compromise."* The guide walks through the artifacts that prove or disprove it, the evidence that corroborates findings, and the pitfalls that derail investigations.

**Artifact-driven**: Start with what you have. *"What can Prefetch tell me?"* The guide explains what the artifact contains, what questions it answers, and what it can't tell you.

### What Every Guide Contains

- **Framing**: What you're investigating and the key questions to answer
- **Evidence**: Which artifacts to examine and what to look for in each
- **Analysis**: How to corroborate findings across multiple sources
- **Pitfalls**: Common mistakes and misinterpretations to avoid
- **Limitations**: What this line of inquiry can't tell you
- **Exit conditions**: When to stop, pivot, or escalate

Guides are available from any page. Mid-investigation, open the sidebar, search for what you're stuck on, and get actionable direction without breaking your workflow.

## Glossary

The glossary is a forensic reference library available everywhere in SIFTed.

### Four Categories

- **Artifacts**: Prefetch, Amcache, ShellBags, Jump Lists, LNK files, SRUM, $MFT, and dozens more. Each entry explains what the artifact is, where to find it, what forensic questions it answers, and what tools parse it.
- **Registry Keys**: Run keys, UserAssist, ShimCache, BAM/DAM, USB device history, and other investigative gold buried in the Windows registry.
- **Persistence Mechanisms**: Services, scheduled tasks, startup folders, WMI subscriptions, and other techniques attackers use to survive reboots.
- **Windows Event Codes**: Security, System, and Application log event IDs that matter—logon events, process creation, service installation, and indicators of tampering.

### Contextual Access

Glossary terms are linked throughout guides and tool interfaces. See an artifact name you don't recognize? It's a link. Click it for the full reference without leaving the page.

The sidebar keeps the glossary one click away from any screen. Search by name, category, or keyword. Build familiarity through repetition until the sidebar stays closed because you already know the answer.

## Workflows

| Category | Tools | What It Does |
|----------|-------|--------------|
| File Carving | Foremost, Scalpel | Recover deleted files from disk images |
| Memory Analysis | Volatility 3 | Extract processes, network connections, malware indicators from RAM dumps |
| Feature Extraction | Bulk Extractor | Scan large datasets for emails, URLs, credit cards, EXIF data |
| Timeline Creation | Plaso (log2timeline) | Build unified timelines from filesystem and artifact timestamps |
| Artifact Parsing | Eric Zimmerman tools | Parse Windows artifacts: Amcache, ShimCache, LNK files, Jump Lists, Event Logs, MFT, registry hives, and mapped SQLite databases |
| Disk Analysis | mmls, fsstat, fls, istat, icat, blkstat, blkcat, blkls, blkcalc | Map partitions, browse filesystems, inspect metadata, extract files, and examine targeted data units |
| File Examination | head, xxd, pdfinfo, pdftotext, file, strings, ExifTool | Read bounded text/hex samples, identify formats, and examine PDF properties and text |

Disk analysis starts at `/disk-analysis`; bounded file examination starts at `/file-examination`. Existing file identification, strings, and metadata workflows provide the corresponding utilities from the sibling SIFTed application. EvtxECmd and MFTECmd remain in Artifact Parsing, with input-signature checks and explicit expected CSV exports.

Partition and file listings preserve raw tool output alongside streaming CSV interpretations. Structured results link to filesystem details, directory browsing, inode inspection, file extraction, and targeted block tools. Offsets are **disk sectors**; block addresses are **filesystem data units**. Set the disk sector size when it differs from the image format or raw-image default. NTFS attribute addresses such as `42-128-1` remain intact for `icat`; `istat` inspects their base metadata record.

Conventional split raw (`.000`/`.001`) and EWF (`.E01`/`.Ex01`) sequences are enumerated explicitly. Every segment gets an identity snapshot and SHA-256; gaps, symlinks, and changed membership are rejected. Select the first segment. Advanced image formats, encrypted containers, and deleted-file recovery depend on the installed Sleuth Kit; a successful extraction does not prove original deleted content is intact.

Completed outputs appear as selectable case inputs. Follow-up examinations retain the producing run and verify the published SHA-256, including when evidence and output roots are separate. Failed or incomplete outputs are not offered as derived inputs. `icat` preserves binary bytes; `blkcat` reads one data unit, and `blkls` reads only unallocated units in a bounded range. Exceeding a sample limit fails the run and marks retained output incomplete.

`blkcalc` output is retained verbatim. For original-to-unallocated mapping, the worker also records a `blkls` allocation listing and computes a verified zero-based stream position, avoiding index-base differences observed in installed tool versions. These positions refer to a complete unallocated stream, not a targeted `blkls` sample.

## Quick Start

Use Python 3.11+ on a SIFT Workstation or Linux machine with the forensic tools installed.

```bash
./sifted setup
export SIFTED_INPUT_ROOTS="/cases,/mnt/evidence"
export SIFTED_OUTPUT_ROOTS="/cases"
./sifted
```

Open `http://127.0.0.1:5000`. `setup` creates a private `.venv` and installs the pinned runtime dependencies. Python's `venv` support and access to the Python package index are required for setup; ordinary launches do not install anything or require a network connection. Forensic tools must already be installed on the workstation.

The launcher runs Gunicorn alongside exactly one job worker, using the same Python interpreter and configuration. Ctrl+C or SIGTERM stops both services. If either service exits unexpectedly, the launcher stops the other and exits with a failure status so a service manager can restart it. Tool execution uses installed binaries independently of the application's virtual environment.

```bash
./sifted --port 8080
./sifted --lan --port 8080
./sifted --help
```

`--lan` binds to `0.0.0.0` and provides unauthenticated access; use it only on a trusted network. The default binds to localhost. The script works from any current directory and through a symlink, so it can also be placed on your PATH. It automatically selects the repository's `.venv`; `SIFTED_PYTHON` can select another Python interpreter explicitly.

To update, stop SIFTed, update the checkout, rerun `./sifted setup`, and start it again. The checkout's `data/sifted.sqlite3` persists across setup runs. Use `SIFTED_DATABASE_PATH` to keep state outside the checkout if replacing the entire directory. Setup does not install or upgrade forensic tools.

## Foundation

Cases, evidence references, jobs, event cursors, and output manifests live in SQLite. Tool adapters validate requests and produce serializable argument lists. Preview and execution use the same plan. A separate worker claims jobs transactionally, verifies inputs, executes subprocesses, and publishes outputs from a private staging folder. The web process never owns a running forensic subprocess.

Jobs move from `queued` to `running`, then `success`, `error`, `cancelled`, or `interrupted`. Queued jobs survive restarts. Interrupted jobs preserve captured output and require an explicit retry in a new folder. Cancellation kills the tool's process group; cancellation closes when output finalization begins. Output folders are reserved permanently for their original jobs.

Each published file has a SHA-256 manifest entry. The `_sifted` directory contains provenance, actual command arguments, executable fingerprints, input hashes, and generated configuration snapshots. Directory inputs record membership and per-file hashes; symbolic links inside directory evidence are rejected. Input identity is checked before and after execution. Files registered to cases additionally carry a baseline SHA-256 that is verified before tools run.

Events are persisted and replayed using `Last-Event-ID`; multiple viewers do not consume each other's events. The frontend also polls terminal status when an event connection fails. CSV rows are indexed into a disposable SQLite cache for pagination, avoiding repeated full-file scans. Viewer sorting, filtering, and CSV export apply to loaded rows; case search scans persisted text results.

Zimmerman workflows use parser-specific native contracts, frozen configuration, registry transaction-log captures and validated exports. SQLite maps use a clearly identified SIFTed executor on vanilla SIFT. See [Zimmerman validation](docs/zimmerman-validation.md) for the native checks and reproducible fixtures.

The previous JSON stores, in-process runners, arbitrary command logging endpoint, local Volatility checkout assumptions, and legacy route aliases have been removed. This release starts with a fresh SQLite case database and does not import old JSON state.

See [the runtime design](docs/runtime.md) for extension points, recovery, and testing. Curated workflows, guides, and the glossary remain the analyst-facing foundation.

## Evidence workspace and direct tools

Open `/evidence` or choose **Evidence workspace** from a case to start with a registered input. The workspace recommends actions from content signatures, native tool capabilities, acquisition type and existing results. The original Tools pages and URLs remain available; both interfaces use the same adapters, durable queue, case history and copyable native CLI examples.

Disk evidence opens an integrated tabbed workspace: **Overview**, **Analysis**, **Triage**, **Derived files**, and **Activity**. Map the disk, analyze a filesystem, and build its recursive inventory directly in Analysis. Successful inventory jobs open Triage automatically. Browse and filter entries, inspect metadata inline, then extract or recover a selected file; completed captures open Derived files. Identify and examine captured content there while keeping the original disk selected. Simple native CLI examples and reports open inside the workspace. [File triage](docs/file-triage.md) describes the workflow and its forensic limits.

Partition offsets, sector sizes, inode/NTFS stream addresses and deletion flags travel with the selected entry. Search can cover the current directory or entire inventory, with entry type and deletion/reallocation filters and 100-row pages. Tabs remember their directory, filters and selected captured file; queued jobs resume monitoring after a reload. Job completion refreshes results automatically, and transient connection failures retry without re-enqueuing work.

Complete extracted, carved and plugin-produced files appear in Derived files; supporting reports stay with their producing runs. Captured content is scoped to descendants of the selected evidence. Raw block samples remain labeled blocks and offer identification, byte and string examination. Activity includes disk work and examination of captured files, with previously completed results available without rerunning a tool. Advanced recovery, timeline and memory configuration remains accessible through the standalone tool entry points.

Raw `.raw` files are ambiguous until their acquisition context is known. Use **Overview → Registered type** to select disk or memory. Recognized content signatures take precedence over misleading names; adapters still validate each preview and execution. Missing tools are shown as unavailable. Viewing or switching tabs does not queue work, and recorded processing does not establish forensic findings.

Guided partition choices use up to 100 rows from a hash-verified map no larger than 1 MiB. Inline reports are escaped and bounded to 128 KiB; complete reports remain accessible. Activity shows the latest 100 runs, with all case results available separately.

Compare **Evidence** and **Tools** against the same case for A/B evaluation. Neither interface requires a separate database or workflow status store.

## Configuration

Web and worker processes must use the same environment and filesystem permissions.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIFTED_DATABASE_PATH` | `data/sifted.sqlite3` | Durable database; keep on a local filesystem |
| `SIFTED_INPUT_ROOTS` | `/cases` | Comma-separated permitted evidence roots |
| `SIFTED_OUTPUT_ROOTS` | `/cases` | Comma-separated permitted output roots |
| `SIFTED_ALLOWED_PATHS` | Input and output roots | Browsing and result viewing roots |
| `SIFTED_SYMBOL_ROOTS` | Empty | Permitted local Volatility symbol directories |
| `SIFTED_VOLATILITY_SYMBOLS` | `~/.cache/sifted/volatility3/symbols` | Writable directory for downloaded Windows symbols |
| `SIFTED_SCALPEL_CONFIG` | `sifted_core/carving_profiles.conf` | Reviewed Scalpel profiles; override with an explicitly enabled custom profile |
| `SIFTED_EZ_ROOT` | `/opt/zimmermantools` | Zimmerman assemblies, RECmd batches, EVTX and SQLite maps |
| `SIFTED_BINARIES` | `{}` | JSON map from tool ID to executable or argument-prefix list |
| `SIFTED_TOOL_TIMEOUT_SECONDS` | `14400` | Whole-job execution deadline |
| `SIFTED_MAX_OUTPUT_BYTES` | `10737418240` | Monitored attempt storage and subprocess output budget |
| `SIFTED_RESULT_FILE_LIMIT` | `12` | Result links shown per job |
| `SIFTED_PORT` | `5000` | Launcher port; `--port` takes precedence |

For example, override an installed tool location without changing its adapter:

```bash
export SIFTED_BINARIES='{"volatility":["/usr/local/bin/vol"],"evtxecmd":["/usr/bin/dotnet","/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"]}'
```

Zimmerman adapters invoke `dotnet` plus the installed assembly directly because some SIFT shell wrappers lose argument boundaries for paths with spaces. SQLite maps use SIFTed's own read-only executor. Volatility discovers canonical plugins and typed options from the installed `vol` console script using its own Python environment. It automatically downloads Windows symbols to a user-writable directory; select offline mode to use available symbols only. Linux and macOS need matching kernel symbol files in an additional directory permitted by `SIFTED_SYMBOL_ROOTS`. No plugin catalog, separate tool checkout, or Volatility dependency in the app virtual environment is needed.

See [Volatility validation](docs/volatility-validation.md) for the tested SIFT installation, real memory fixture, coverage, and reproduction commands.

For a persistent deployment, configure your service manager to run the absolute path to `sifted` as the analyst account, with the configuration above in its environment. The launcher supervises both services, so only one service unit is needed. Allow at least 20 seconds for shutdown. Gunicorn runs two HTTP processes with eight threads each; forensic jobs stay serial in the separate worker. `/api/health` reports the worker heartbeat.

## Verification

```bash
pip install -r requirements-dev.txt
pytest -q
ruff check app.py sifted_core tests --select F
```

Deterministic tests exercise all adapters and the shared worker, including cancellation, subprocess deadlines, integrity failures, concurrent claims, output preservation, restart recovery, and event replay. Tests marked `live` use real installed tools and skip unavailable installations.

The GitHub Actions workflow runs the deterministic suite on Python 3.11, 3.12, and 3.14, plus a separate Chromium job. Live forensic tools are validated on SIFT rather than installed into CI.

Optional real-browser checks:

```bash
pip install -r requirements-browser.txt
python -m playwright install chromium
pytest -m browser -q
```

Real SIFT smoke tests cover strings (ASCII and UTF-16), ExifTool CSV/JSON, MIME mismatches, Foremost and Scalpel byte-for-byte recovery, audit offsets, profiles, limits and cancellation, Bulk Extractor, Plaso extraction/export, and LECmd parsing of a synthetic Unicode shortcut. Synthetic partitioned ext4 images exercise all nine Sleuth Kit tools, exact binary extraction, allocation and mapping, and 4,096-byte sector geometry. A generated PDF exercises Poppler; a generated NTFS filesystem exercises extraction and MFTECmd parsing of its MFT. Volatility tests use a separately downloaded, digest-pinned public Windows memory image for triage, CLI comparisons, process extraction, auxiliary strings analysis and cancellation. Browser checks follow filesystem extraction and carving recovery tables into hash-verified derived examination. [Carving validation](docs/carving-validation.md) records native-tool limits, including DOC/OLE misses on the tested Foremost build. Fixtures and output paths are temporary and include spaces. Large memory images and comprehensive EVTX fixtures are not bundled; coverage is documented for the tested inputs and versions.
