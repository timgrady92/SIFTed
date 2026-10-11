# SIFTed

> **Note**: Full disclosure, this version of the application is purely developed using a mixture of Claude Code and Codex. I would love to get this concept in front of a dedicated team of developers. The mission statement of this design is simple: allow junior DFIR analysts to meaningfully contribute on day one of the job while getting exposure to the concepts. Best case: the analyst outgrows the tool within six months.

> **Note**: Tool integration is currently in development. Workflows are being introduced slowly and methodically after rigorous testing. Existing workflows should be treated as experimental at best.

**Training wheels for forensic analysts.**

Most forensic tools assume you already know what you're doing. SIFTed assumes you're learning.

Every workflow shows the exact commands that will run. Every output links back to the artifacts that matter. Every guide explains not just *what* to look for, but *why* it matters and *when* to stop looking.

**We measure success by obsolescence.** An analyst who needs SIFTed indefinitely isn't learning—they're dependent. The goal is internalized knowledge, not a permanent crutch.

## How It Works

### Day One Value

Junior analysts can run complex forensic workflows immediately:

- **File carving** with Foremost and Scalpel—select file types, click run, review recovered files
- **Memory analysis** with Volatility 3—choose investigation bundles like "Malware + Evasion" or "Network Activity"
- **Bulk feature extraction**—scan disk images for emails, URLs, credentials, and other high-value indicators
- **Timeline creation** with Plaso—build CSV timelines from host artifacts
- **Artifact parsing** with Eric Zimmermann tools—extract evidence from Prefetch, Amcache, Event Logs, and more

No command-line memorization required. No syntax errors. No wasted cycles on typos.

### Transparent Learning

Every action teaches:

- **Command preview**: See exactly what will execute before running. Read it. Understand it. Eventually, type it yourself.
- **Integrated glossary**: Hover over forensic terms for instant definitions. Artifacts, registry keys, persistence mechanisms, Windows event codes—all searchable and contextual.
- **Investigation guides**: Hypothesis-driven playbooks that frame problems, identify evidence sources, warn about pitfalls, and define exit conditions.

The UI is explicit about what it's doing. Nothing is hidden. Nothing is magic.

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
| Artifact Parsing | Eric Zimmermann tools | Parse Windows artifacts: Prefetch, Amcache, LNK files, Jump Lists, Event Logs, MFT |

## Quick Start

Use Python 3.11+ on a SIFT Workstation or Linux machine with the forensic tools installed.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SIFTED_INPUT_ROOTS="/cases,/mnt/evidence"
export SIFTED_OUTPUT_ROOTS="/cases"
python app.py
```

Open `http://127.0.0.1:5000`. The local launcher starts one worker alongside the web server. If the worker exits, the launcher stops the web server. Tool execution uses installed binaries independently of the application's virtual environment.

## Foundation

Cases, evidence references, jobs, event cursors, and output manifests live in SQLite. Tool adapters validate requests and produce serializable argument lists. Preview and execution use the same plan. A separate worker claims jobs transactionally, verifies inputs, executes subprocesses, and publishes outputs from a private staging folder. The web process never owns a running forensic subprocess.

Jobs move from `queued` to `running`, then `success`, `error`, `cancelled`, or `interrupted`. Queued jobs survive restarts. Interrupted jobs preserve captured output and require an explicit retry in a new folder. Cancellation kills the tool's process group; cancellation closes when output finalization begins. Output folders are reserved permanently for their original jobs.

Each published file has a SHA-256 manifest entry. The `_sifted` directory contains provenance, actual command arguments, executable fingerprints, input hashes, and generated configuration snapshots. Directory inputs record membership and per-file hashes; symbolic links inside directory evidence are rejected. Input identity is checked before and after execution. Files registered to cases additionally carry a baseline SHA-256 that is verified before tools run.

Events are persisted and replayed using `Last-Event-ID`; multiple viewers do not consume each other's events. The frontend also polls terminal status when an event connection fails. CSV rows are indexed into a disposable SQLite cache for pagination, avoiding repeated full-file scans. Viewer sorting, filtering, and CSV export apply to loaded rows; case search scans persisted text results.

The previous JSON stores, in-process runners, arbitrary command logging endpoint, local Volatility checkout assumptions, and legacy route aliases have been removed. This release starts with a fresh SQLite case database and does not import old JSON state.

See [the runtime design](docs/runtime.md) for extension points, recovery, and testing. Curated workflows, guides, and the glossary remain the analyst-facing foundation.

## Configuration

Web and worker processes must use the same environment and filesystem permissions.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIFTED_DATABASE_PATH` | `data/sifted.sqlite3` | Durable database; keep on a local filesystem |
| `SIFTED_INPUT_ROOTS` | `/cases` | Comma-separated permitted evidence roots |
| `SIFTED_OUTPUT_ROOTS` | `/cases` | Comma-separated permitted output roots |
| `SIFTED_ALLOWED_PATHS` | Input and output roots | Browsing and result viewing roots |
| `SIFTED_SYMBOL_ROOTS` | Empty | Permitted local Volatility symbol directories |
| `SIFTED_PLUGIN_CATALOG` | `data/volatility_plugins.json` | Supported plugin names |
| `SIFTED_FOREMOST_CONFIG` | `/etc/foremost.conf` | Installed carving signatures |
| `SIFTED_SCALPEL_CONFIG` | `/etc/scalpel/scalpel.conf` | Installed carving signatures |
| `SIFTED_EZ_ROOT` | `/opt/zimmermantools` | Zimmerman assemblies and RECmd batch configuration |
| `SIFTED_BINARIES` | `{}` | JSON map from tool ID to executable or argument-prefix list |
| `SIFTED_TOOL_TIMEOUT_SECONDS` | `14400` | Whole-job execution deadline |
| `SIFTED_MAX_OUTPUT_BYTES` | `10737418240` | Monitored attempt storage and subprocess output budget |
| `SIFTED_RESULT_FILE_LIMIT` | `12` | Result links shown per job |
| `SIFTED_PORT` | `5000` | Local launcher port |

For example, override an installed tool location without changing its adapter:

```bash
export SIFTED_BINARIES='{"volatility":["/opt/volatility/bin/vol"],"evtxecmd":["/usr/bin/dotnet","/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"]}'
```

Zimmerman adapters prefer `dotnet` plus the installed assembly because some SIFT shell wrappers lose argument boundaries for paths with spaces. Volatility runs offline and uses configured local symbols or its installed cache.

For a WSGI deployment, run the web service and exactly one worker separately:

```bash
pip install gunicorn
python -m sifted_core.worker
# In a second terminal with the same environment:
gunicorn --bind 127.0.0.1:5000 --workers 2 --threads 8 --timeout 0 wsgi:app
```

Use your service manager to supervise both processes. `/api/health` reports the worker heartbeat. This application is intended for a trusted local analyst environment; the launch commands bind to localhost.

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

Real SIFT smoke tests cover strings (ASCII and UTF-16), ExifTool CSV/JSON, MIME mismatches, normal/safe Foremost, Scalpel, Bulk Extractor, Plaso extraction/export, and LECmd parsing of a synthetic Unicode shortcut using temporary synthetic evidence and paths containing spaces. Comprehensive Windows artifact and memory fixtures are not bundled; those parsers are covered by deterministic adapter tests and installation discovery, not by claims of forensic validation.
