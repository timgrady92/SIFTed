# Guided memory analysis

Memory evidence uses the same intake, evidence tabs, job queue, tool adapter, results, custody and derived-file examination as disk evidence. The memory journey adds analytical choices to that framework; it has no separate executor or workflow database. The standalone Volatility examiner remains available.

## Analyst journey

1. **Prepare:** intake automatically selects the memory workflow when native structures support it. Detected Windows context sets the OS and keeps its selector under **Analysis settings**. Identify the image, then build an unfiltered process inventory. Windows uses `windows.info.Info`; Linux and macOS use kernel banners to help establish the required symbols. When intake cannot resolve acquisition context, select **Memory image** through **Set evidence type** or **Choose another workflow**. Acquisition choices are recorded independently of the original profile, and filenames never establish the workflow.
2. **Processes:** search recorded values, compare names, PIDs, parent PIDs and timestamps, and inspect a row. PPID cells include the matching process name and link to its inspector. **Children (N)** inside the inspector discloses matching child records. Links search the whole selected inventory, open the appropriate page and retain that inventory; Back restores the prior search, selection, disclosures and position. Command-line, loaded-module/library/mapping and supported executable extraction actions use that process's PID. The complete process record and corroborating tree/scan actions are available through disclosure panels. A scanner hit alone does not establish a hidden or malicious process.
3. **Investigate:** choose a question about network activity, injection, services/registry, kernel integrity or indicators. Only the relevant examinations appear. Reports support search, paging and links back to uniquely recorded PIDs in the verified process inventory. A link identifies an inventory row; it does not resolve PID reuse or establish that two recovered objects represent the same process instance. The question guidance explains what needs corroboration.
4. **Examine files:** extracted material joins the existing captured-file workflow. File identification, byte/string inspection, applicable parsers and local ClamAV scans use the same adapters as disk-derived files. The original memory image stays selected, and captured files retain their producing run, process selection and hashes. Plugin reports and saved configurations remain reports, not new evidence items. Extraction may recover incomplete bytes.

Actions show concise native CLI examples using the absolute capture path and selected PID. Run completion refreshes the current stage without navigating away. Process filters and selections persist across tabs; queued jobs resume monitoring after reload. Saved process views are separated by acquisition OS. The existing Activity tab includes analysis of the capture and its derived files.

The essential process actions are:

| Context | Inventory | Process examinations | Corroboration |
| --- | --- | --- | --- |
| Windows | `windows.pslist.PsList` | `windows.cmdline.CmdLine`, `windows.dlllist.DllList`, `windows.pslist.PsList --dump` | `windows.pstree.PsTree`, `windows.psscan.PsScan` |
| Linux | `linux.pslist.PsList` | `linux.psaux.PsAux`, `linux.library_list.LibraryList`, `linux.pslist.PsList --dump` | `linux.pstree.PsTree` |
| macOS | `mac.pslist.PsList` | `mac.psaux.Psaux`, `mac.proc_maps.Maps` | `mac.pstree.PsTree` |

Additional process examinations appear in expandable groups: security/object context, injection and mappings, memory capture and known indicators. Windows offers handles, environment, SIDs/privileges, Malfind, loader lists, VADs, process-memory and injection-region extraction, and process YARA. Linux offers open files, environment, history, sockets, Malfind and process YARA; macOS offers open files, sockets, history and Malfind. Registry extraction offers names from a verified unfiltered hive report and passes the selected full name to the native filter. This avoids making recovery of every hive a prerequisite for recovering one available hive. Missing pages can still make a selected recovery fail or be incomplete.

These are guided choices, checked against the installed plugin catalog and option declarations. Unavailable or incompatible actions explain why they cannot run. PID options use each plugin's declared scalar/list type, including Linux `pids` and Windows Memmap's scalar `pid`. Windows network actions require a verified NT version of at least 6; XP captures explain the limitation. The full plugin examiner remains available. The [research and examination map](memory-investigation-research.md) connects these choices to professional methodology.

Indicator work reuses the strings and Bulk Extractor adapters and Volatility's typed YARA file requirement. ASCII and UTF-16LE results are distinct. YARA examinations default to the [bundled memory indicators](yara-rules.md), selected from Google GCTI, Mandiant and ESET. Each run snapshots the exact rules, source manifest and licenses through shared configuration provenance. Analysts can instead select a custom absolute file path under a permitted input root; those files are hashed and checked as auxiliary inputs. No rules are downloaded automatically.

ClamAV is a shared file examination adapter available for captured files and through the existing File Examination page. It loads explicit local databases from `SIFTED_CLAMAV_DATABASE` (default `/var/lib/clamav`), records their hashes and the engine version, and checks database identity before and after execution. It accepts files up to 512 MiB and uses a 1 GiB expanded scan limit. Exit code 1 with a consistent report records signature findings as a successful examination; errors, missing summaries and exceeded limits fail. No matches do not establish safety. Databases remain installed workstation resources, not bundled signature copies; reproducing the exact scan requires retaining the recorded database versions externally.

Windows symbol acquisition uses the adapter's existing writable symbol store. Linux/macOS need matching kernel symbols, as described in [Volatility's installation instructions](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md). Configure permitted symbol paths in the standalone examiner; subsequent guided actions inherit symbol/offline settings from successful same-OS work on this image. Missing symbols produce an ordinary failed job with its diagnostic log and do not unlock a completed inventory.

## Shared result and selection boundary

`memory_analysis.py` projects stages from successful ordinary Volatility runs. An existing unfiltered JSON or JSON Lines inventory from the standalone examiner participates automatically when its case, source path and verified input digest match. Failed runs, PID-filtered results, extraction runs and other OS inventories cannot silently become the complete process list. Analysts can select a previous eligible inventory explicitly.

`published.py` provides one complete-result read boundary for disk inventories, memory inventories and inline reports. It checks the output manifest, allowed path, file type, SHA-256 and stable file identity, retaining the verified descriptor through consumption. Symlinks and altered results are rejected. Structured reports preserve typed integers and nested tree rows; they are paged 50 rows at a time. JSON Lines and CSV are streamed, JSON is limited to 64 MiB, and the reader's file limit is 1 GiB. Text previews show at most 128 KiB. Complete reports remain accessible through the existing report links.

A process selection identifies its inventory run, canonical plugin and one-based row ordinal, rather than trusting a PID supplied by the browser. Submission resolves the published row and verifies that the requested plugin and options match the permitted examination for that PID. The primary input record retains the row, PID and inventory input digest. The worker revalidates the context after queue waiting and performs its normal image integrity checks. The model deliberately describes a PID-scoped examination; it does not claim that PID alone distinguishes every object a corrupted image or remnant scan might contain.

`memory_processes.py` supplies the shared inventory index for parent/child navigation and report PID links. Relationships use the selected unfiltered inventory and its verified result manifest, including native Windows, Linux and macOS name/timestamp fields. Parent links require a unique matching PID. Zero, missing or malformed PPIDs, duplicate parent PIDs, self/cyclic references and contradictory available lifetimes stay unlinked with a brief status. Missing timestamps cannot corroborate ancestry; these remain recorded PPID matches, not proof of origin or execution causality. Children lists retain distinct row identities, including records with duplicate child PIDs. Navigation requires no additional tool runs, dependencies or stored relationship database.

To extend the guided choices, add an analytical action to the profile using a canonical installed plugin and its declared PID option. Continue using the same adapter, selection validation, worker and result model. New evidence source types should reuse the workspace's tab descriptors and shared execution/result components.

## Validation

The connected vanilla SIFT installation's Volatility 3 2.27.0 completed this guided journey against the digest-pinned public Windows XP capture documented in [Volatility validation](volatility-validation.md): kernel identification, 47 processes, selection of `explorer.exe` PID 1812, command-line and loaded-module examination, executable extraction and derived-file examination. The test checks the extracted PE header, recorded process provenance and unchanged source SHA-256. It uses isolated temporary case state and outputs.

```bash
SIFTED_TEST_MEMORY_IMAGE=/tmp/sifted-memory-test/windows.img \
  .venv/bin/python -m pytest -q \
  tests/test_live_evidence_workspace.py::test_native_workspace_guided_memory_analysis
```

Deterministic tests cover all three OS profiles, catalog changes, both structured renderers, paging/search, exact 64-bit values, filtered-inventory exclusion, forged selection rejection, and published-result changes before submission and while queued. Chromium exercises the full journey at 390- and 1440-pixel widths, including reload recovery, distinct concurrent plugin jobs, tab/OS state, inline reports and captured-file navigation. These unit fixtures are test contracts, not demonstration evidence.

Process relationship checks cover absent/duplicate PIDs, invalid identifiers, self/cyclic references, conflicting lifetimes, native timestamp fields, inventory isolation and changed report bytes. Desktop and phone browser checks follow parents outside a filtered page, disclose children on another page, and restore search, selection, expanded details, keyboard focus and scroll position through Back/Forward. Native checks on SIFT resolved Citadel's `svchost.exe` PID 640 to `services.exe` PID 452 and the XP capture's PID 740 to PID 580; an isolated SIFT server also passed the parent/children browser flow at both widths. No extra analysis jobs are created by navigation.

```bash
SIFTED_TEST_INVESTIGATION_IMAGE=/cases/demo/memory/citadeldc01.mem \
SIFTED_TEST_MEMORY_IMAGE=/cases/demo/memory/windows-xp.img \
  .venv/bin/python -m pytest -q tests/test_live_memory_investigation.py -k native_process_relationships
```

The expanded native investigation also passes on the original 2 GiB Citadel DC01 capture: every guided Windows process action, network/injection/service/kernel examinations, selected hive extraction, process YARA, Bulk Extractor and shared captured-file examination, including ClamAV's detection outcome. [Reproduction commands and observed limits](volatility-validation.md#expanded-investigation-on-a-real-incident-exercise) document the sample hashes, direct CLI comparison and unreadable-hive behavior. Tests cover recorded hive choices, report-to-process navigation, ambiguous PID rejection, bundled/custom rules and scanner database changes.

Automatic intake was checked through Chromium against an isolated server on the SIFT workstation. Citadel DC01 entered without a declared type; native libmagic reported `application/etl`, while Volatility validated Windows memory mappings. The memory tabs opened automatically with Windows settings collapsed. Image identification and inventory then returned 40 processes, including `explorer.exe` PID 3472. Re-verification preserved the original SHA-256 and supported profile; no analyst classification event was needed. Native intake tests also identified an extensionless copy and the complete 2 GiB upload named `misleading.jpg`.

```bash
SIFTED_TEST_INVESTIGATION_IMAGE=/cases/demo/memory/citadeldc01.mem \
  .venv/bin/python -m pytest -q tests/test_live_evidence_assessment.py
```

The [intake documentation](evidence-intake.md#profiles-and-custody) describes probe limits and reuse. Desktop and phone regression tests cover automatic routing, concealed detection details, failed manual saves and changing an unresolved acquisition's workflow.

Successful Linux and macOS kernel analysis has not been established with real captures in this validation. Their profile/adapter contracts are tested; real captures and matching symbols remain necessary for native validation. No new forensic binaries or workstation dependencies were installed for this workflow.
