# SIFTed

SIFTed is a web UI for SANS SIFT workstation workflows. It provides guided, offline-ready interfaces for common forensic tasks, with transparent command previews and consistent run tracking.

## What SIFTed Provides

- Case-centric workflows for file carving, memory analysis, and bulk feature extraction.
- Guided inputs with validated paths and auto-filled defaults.
- Command previews so analysts can see exactly what will run before execution.
- Saved runs per case with re-openable outputs and logs.

## Key Workflows

### Cases
- Track evidence paths, summaries, and file hashes.
- Each case keeps a history of runs for the supported tools.
- Outputs are stored under `/cases/<case>/...` using timestamps.

### Foremost (File Carving)
- Build focused carve profiles using common file types.
- Optional quick and verbose modes.
- Output summaries include counts by file extension.

### Scalpel (File Carving)
- Generate a scoped config based on selected file types.
- Run Scalable carves with transparent command previews.
- Review results directly in the UI.

### Bulk Extractor
- Choose scanner presets or build a custom scanner list.
- Info mode for faster surveys of large evidence sets.
- Histograms enabled by default for quick triage.

### Volatility 3 (Memory Analysis)
- OS tabs for Windows, Linux, and macOS plugins.
- Linux triage bundles plus full manual plugin selection.
- Output rendered to JSON or table formats.
- Bundled, offline symbol usage (no network access required).

### Artifact Triage (Timeline)
- Plaso-based timeline creation with log2timeline and psort.
- Outputs include a `.plaso` storage file and CSV timeline for review.

## Requirements

- Python 3.11+ recommended.
- Local install of the tool binaries you intend to use (Foremost, Scalpel, Bulk Extractor).
- Volatility 3 is already included in this repository at `volatility3/`.

## Production Configuration

SIFTed defaults to safe path access for browsing and output writes. Set the following
environment variables to align with your environment:

- `SIFTED_SECRET_KEY`: Flask secret key (required for production).
- `SIFTED_ALLOWED_PATHS`: Comma-separated list of roots that the file browser and viewer can access (default: `/cases`).
- `SIFTED_OUTPUT_ROOTS`: Comma-separated list of roots that output paths may write under (default: `/cases`).
- `SIFTED_LOG_LEVEL`: Logging level (default: `INFO`).

Example:

```bash
export SIFTED_SECRET_KEY="replace-with-random-secret"
export SIFTED_ALLOWED_PATHS="/cases,/mnt/evidence"
export SIFTED_OUTPUT_ROOTS="/cases"
export SIFTED_LOG_LEVEL="INFO"
```

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

For production deployments, run via a WSGI server, for example:

```bash
gunicorn --bind 0.0.0.0:5000 wsgi:app
```

## Usage Tips

- Use the file browser to select evidence paths from `/cases` or other mounted locations.
- Keep outputs under `/cases` for consistent result tracking.
- For offline use, ensure required symbol sets are available in the bundled Volatility cache.

## Outputs and Logs

- Each run writes a log file alongside the output folder (for example, `/cases/<case>/volatility/<timestamp>.log`).
- Volatility outputs are saved under `results/` inside the run folder.
- The Cases view links back to output files for quick review.

## Intended Audience

SIFTed is designed for forensic analysts who want a fast, consistent UI for common workflows without sacrificing command-line transparency.
