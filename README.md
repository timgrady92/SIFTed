# SIFTed

SIFTed is a web interface for digital forensics on a SIFT Workstation, built to help analysts move from evidence to reviewable results. Create a case, upload files or register workstation paths, and let SIFTed hash and identify the evidence before analysis. The evidence workspace guides disk investigations through partition mapping, filesystem inventory, file inspection and recovery. Memory investigations use Volatility 3 to identify captures, review processes and parent–child relationships, investigate network activity and injection, and examine recovered files.

Available workflows include Windows artifact parsing with Eric Zimmerman tools, file carving with Foremost and Scalpel, feature extraction with Bulk Extractor, timelines with Plaso, and file examination with strings, ExifTool, hex views and PDF utilities. Memory examinations include a bundled YARA rule library; captured files can be scanned with local ClamAV signatures. Results stay with their case, alongside logs, input hashes and output manifests, and recovered files can feed subsequent examinations. Copyable native terminal commands, investigation guides and a searchable glossary help analysts understand and reproduce the work. [Public demonstration evidence](demos/README.md) provides practice samples with known findings.

Run on Linux with Python 3.11+ and the forensic tools you need already installed. From the checkout, run `./sifted setup`, then `./sifted`, and open <http://127.0.0.1:5000>. Evidence and results default to `/cases`; set `SIFTED_INPUT_ROOTS` and `SIFTED_OUTPUT_ROOTS` to your readable evidence and writable results directories before launching. Setup installs the application's Python dependencies; forensic tools and matching memory symbols are prepared separately. See the [runtime documentation](docs/runtime.md), [memory analysis guide](docs/memory-analysis.md) and [symbol setup guide](docs/volatility-symbols.md) for details.

![Verified public demonstration evidence organized in the case workspace](docs/screenshots/evidence-workspace.png)

<details>
<summary>Disk file triage and metadata inspection</summary>

![Disk file triage with filesystem entries and inline metadata inspection](docs/screenshots/disk-file-triage.png)

</details>

<details>
<summary>Memory process inspection and native terminal commands</summary>

![Memory process inspection with Volatility results and a native terminal command](docs/screenshots/memory-process-inspection.png)

</details>
