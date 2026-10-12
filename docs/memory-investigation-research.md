# Research informing the memory workflow

Reviewed 2026-10-11. These recommendations inform analytical questions, not automated malware verdicts. The implementation uses the connected SIFT workstation's native tools and the shared SIFTed runtime. The [workflow contract](memory-analysis.md) describes its implementation and validation.

## Method and interpretation

Chad Tilbury's SANS Memory Forensics Cheat Sheet organizes examination around suspicious processes, their objects, network artifacts, injection, kernel anomalies and extracted objects. SIFTed adapts those questions into four focused stages: Prepare → Processes → Investigate → Examine files. This is our UI design decision, not a claim that every investigation must follow a fixed sequence. The source includes multiple tools and historical command forms; installed Volatility 3 capabilities determine our actual commands. [SANS poster and download](https://www.sans.org/posters/memory-forensics).

CSIRT-MU's practical memory notebook follows an observable lead through network results, suspicious executable memory and extracted objects. That supports moving between a report and its process context rather than running every plugin indiscriminately. Its CAPA examination is useful follow-on work, but CAPA is not installed on the connected workstation, so it is not a dependency or a claimed available action. [CSIRT-MU memory analysis](https://notebooks.csirt.muni.cz/hands-on/memory/).

Volatility describes Malfind as finding potentially injected regions. Security products can also produce apparent hooks or other suspicious structures. SIFTed asks analysts to compare mappings, loader lists, ownership and process behavior; neither a hit nor an empty result becomes a malware verdict. [Malfind reference](https://volatility3.readthedocs.io/en/stable/volatility3.plugins.windows.malware.malfind.html), [Volatility's security-product false-positive example](https://volatilityfoundation.org/when-anti-virus-engines-look-like-kernel-rootkits/).

## Questions translated into examinations

| Question | SIFTed examinations | What to compare |
| --- | --- | --- |
| Is this a usable capture? | Acquisition context, Windows kernel information or kernel banners, unfiltered process inventory | Acquisition details, OS, symbol availability and parser diagnostics |
| Which processes need attention? | Process list/tree/remnant scan; selected command line, modules, handles, environment and security context | Parent relationships, timestamps, paths, expected purpose; remnants may be terminated processes |
| What network activity is represented? | Windows NetStat/NetScan; Linux socket/interface enumeration; macOS sockets | Endpoints, ports, state, timestamps and owner; stale records and PID reuse require care |
| Is there evidence of injection? | Malfind, Windows loader-list comparison and virtual memory regions, process-enumeration comparison | Region protections, paths, bytes and process context; executable memory is not inherently malicious |
| What might explain persistence? | Windows service and hive enumeration, hive extraction into shared registry examination | Service binary paths/start modes and registry evidence, corroborated with disk and logs |
| Are kernel structures consistent? | Module enumeration/scanning and supported dispatch/system-call examinations | Address ownership, paths, known software, unloaded remnants and capture gaps |
| Can known indicators narrow the search? | Reviewed YARA rules, ASCII/UTF-16LE strings, Bulk Extractor email/URL features | Rule meaning, encoding and location; text matches alone do not prove execution or communication |
| What do recovered bytes show? | Executable, process-memory, region and hive captures where supported; shared file/hex/strings/registry tools and local ClamAV | Recovery completeness, producing run/PID, hashes and corroborating artifacts |

Windows network plugins are not universal across Windows versions. The installed NetScan/NetStat implementations need NT 6 or newer; the verified `NtMajorVersion` result controls the guided actions. Older captures retain the plugin examiner and strings/feature examinations, with their limitations stated. [NetScan implementation and requirements](https://volatility3.readthedocs.io/en/stable/volatility3.plugins.windows.netscan.html).

GNU strings supports whole-file scanning, alternate character encodings and byte offsets. SIFTed retains separate ASCII and UTF-16LE examinations. These offsets describe the input byte stream, not a virtual process address. Bulk Extractor's feature files provide another way to narrow examination; the installed `email` scanner supplies the selected email/URL work. [GNU strings manual](https://sourceware.org/binutils/docs/binutils/strings.html), [Bulk Extractor manual source](https://github.com/simsong/bulk_extractor/blob/main/doc/latex_manuals/BECurrentGuide.tex).

YARA executes inside the installed Volatility environment. A rule file is a required analyst input, recorded and checked through the ordinary auxiliary-file mechanism. Windows and Linux use mapped-process scans; the macOS image action explicitly describes its generic byte scan. No unreviewed rule pack is downloaded. [Volatility VadYaraScan implementation](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/vadyarascan.py).

Volatility's malware-detection example pairs extracted memory objects with ClamAV. We retain that local examination pattern, updating execution to native Volatility 3 and a normal file-scanning adapter. ClamAV requires signature databases and imposes scan limits; its own documentation cautions about false positives. SIFTed records the engine and database hashes, checks database stability, treats a detection as a completed examination, and treats errors or exceeded limits as incomplete. It does not remove or quarantine evidence. [Volatility extraction/scanning example](https://volatilityfoundation.org/automating-detection-of-known-malware-through-memory-forensics/), [ClamAV scanning documentation](https://docs.clamav.net/manual/Usage/Scanning.html).

## Scope and workstation fit

The connected workstation provides Volatility 3 2.27.0, GNU strings, Bulk Extractor 1.6.1, file/xxd and ClamAV 1.5.4. YARA support is present within Volatility's Python environment. No forensic packages were installed for this work. MemProcFS, CAPA, FLOSS and a standalone YARA CLI were not found; SIFTed does not present them as available or add fallback executors for them.

The new choices are declarative entries in `memory_catalog.py`. Installed plugin names, requirement types and native adapters remain authoritative. Missing capabilities explain their unavailability. Ordinary runs supply stage progress, and existing standalone entry points remain usable. There is no second memory database, pipeline engine or compatibility alias catalog.

Native validation uses the unmodified public Citadel DC01 acquisition from DFIR Madness's *The Stolen Szechuan Sauce* case, also used in CSIRT-MU's exercises, plus the existing official Volatility XP fixture. Large acquisitions are downloaded outside the repository. [Original case](https://dfirmadness.com/the-stolen-szechuan-sauce/), [CSIRT-MU exercise preparation](https://notebooks.csirt.muni.cz/preparation/tutorial/).
