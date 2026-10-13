# SIFTed

SIFTed is a web interface for digital forensics on a SIFT Workstation, built to help analysts move from evidence to reviewable results. Create a case, upload files or register workstation paths, and let SIFTed hash and identify the evidence before analysis. The evidence workspace guides disk investigations through partition mapping, filesystem inventory, file inspection and recovery. Memory investigations use Volatility 3 to identify captures, review processes and parent–child relationships, investigate network activity and injection, and examine recovered files.

Available workflows include Windows artifact parsing with Eric Zimmerman tools, file carving with Foremost and Scalpel, feature extraction with Bulk Extractor, timelines with Plaso, and file examination with strings, ExifTool, hex views and PDF utilities. Memory examinations include a bundled YARA rule library; captured files can be scanned with local ClamAV signatures. Results stay with their case, alongside logs, input hashes and output manifests, and recovered files can feed subsequent examinations. Copyable native terminal commands, investigation guides and a searchable glossary help analysts understand and reproduce the work. [Public demonstration evidence](demos/README.md) provides practice samples with known findings.

## Install on your SIFT Workstation

Install and run SIFTed **directly inside your SIFT Workstation**, where the forensic tools and evidence are accessible. In a SIFT terminal, use Git and Python 3.11+ with `venv` support to clone the repository and install its Python dependencies. The example below creates evidence and results directories in your home folder; change those paths to suit your case storage. SIFTed uses the workstation's installed forensic tools; `setup` installs only the application's Python dependencies.

```bash
git clone https://github.com/timgrady92/SIFTed.git
cd SIFTed
./sifted setup

mkdir -p "$HOME/sifted-cases/evidence" "$HOME/sifted-cases/results"
export SIFTED_INPUT_ROOTS="$HOME/sifted-cases/evidence"
export SIFTED_OUTPUT_ROOTS="$HOME/sifted-cases/results"
./sifted
```

Open <http://127.0.0.1:5000> in the SIFT Workstation's browser, create a case, and add evidence. Keep the same directory settings when you relaunch; without them, both roots default to `/cases`. For tool configuration and memory prerequisites, see the [runtime documentation](docs/runtime.md), [memory analysis guide](docs/memory-analysis.md) and [symbol setup guide](docs/volatility-symbols.md).

## Evidence workflows

![Verified public demonstration evidence organized in the case workspace](docs/screenshots/evidence-workspace.png)

<details>
<summary>Disk file triage and metadata inspection</summary>

![Disk file triage with filesystem entries and inline metadata inspection](docs/screenshots/disk-file-triage.png)

</details>

<details>
<summary>Memory process inspection and native terminal commands</summary>

![Memory process inspection with Volatility results and a native terminal command](docs/screenshots/memory-process-inspection.png)

</details>

## Guides and glossary

**Guides** provide searchable playbooks for starting with a hypothesis, such as suspected phishing or data theft, or with an artifact you need to understand. Each playbook connects investigative questions to evidence sources, corroboration, pitfalls, limitations and stopping points. **Glossary** is a searchable forensic reference covering artifacts, registry keys, persistence locations and Windows event codes, with operating-system filters, evidence locations and interpretation guidance. Open either from the navigation bar; contextual artifact links in the guides connect the playbooks to the reference material.

![Searchable investigation guides organized by hypothesis and artifact](docs/screenshots/investigation-guides.png)

<details>
<summary>Inside a guide: investigating a suspected phishing email</summary>

![Phishing investigation playbook showing questions and evidence sources](docs/screenshots/investigation-playbook.png)

</details>

![Forensic glossary with the Prefetch reference open](docs/screenshots/forensic-glossary.png)
