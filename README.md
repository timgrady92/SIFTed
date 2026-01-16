# SIFTed

> **Note**: Tool integration is currently in development. Workflows are being introduced slowly and methodically after rigorous testing.

**Training wheels for forensic analysts.**

SIFTed is a guided interface for SANS SIFT workstation workflows. It lets junior analysts contribute meaningful work on day one while building the knowledge to outgrow it.

## Philosophy

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

## The Goal

SIFTed is scaffolding. Scaffolding comes down.

When an analyst can run the underlying tools directly, explain what each one does, and build their own workflows without guidance—they've outgrown the training wheels. That's the win.

## Workflows

| Category | Tools | What It Does |
|----------|-------|--------------|
| File Carving | Foremost, Scalpel | Recover deleted files from disk images |
| Memory Analysis | Volatility 3 | Extract processes, network connections, malware indicators from RAM dumps |
| Feature Extraction | Bulk Extractor | Scan large datasets for emails, URLs, credit cards, EXIF data |
| Timeline Creation | Plaso (log2timeline) | Build unified timelines from filesystem and artifact timestamps |
| Artifact Parsing | Eric Zimmermann tools | Parse Windows artifacts: Prefetch, Amcache, LNK files, Jump Lists, Event Logs, MFT |

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Requirements

- Python 3.11+
- SIFT Workstation (or equivalent tool installations)
- Local binaries: Foremost, Scalpel, Bulk Extractor, Volatility 3, log2timeline/psort, Eric Zimmermann tools

## Configuration

Set environment variables for production deployment:

```bash
export SIFTED_SECRET_KEY="your-secret-key"
export SIFTED_ALLOWED_PATHS="/cases,/mnt/evidence"
export SIFTED_OUTPUT_ROOTS="/cases"
```

For production, run via WSGI:

```bash
gunicorn --bind 0.0.0.0:5000 wsgi:app
```

## License

MIT
