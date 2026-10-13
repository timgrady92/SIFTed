# Volatility 3 validation

The connected SIFT workstation supplies `/usr/local/bin/vol`, using `/opt/volatility3/bin/python3` and framework version 2.27.0. This matches [SIFT's standard provisioning state](https://github.com/teamdfir/sift-saltstack/blob/master/sift/python3-packages/volatility3.sls). SIFTed uses that installation through its normal console script; the app virtual environment does not need Volatility. Discovery currently exposes 167 nondeprecated plugins and 191 typed options. The live discovery test checks every plugin and advertised option against the installed CLI help. Installation snapshots include CLI and plugin source hashes; each successful plugin saves its resolved framework configuration beside its results.

The workstation's installed symbol directories are root-owned. A direct Windows analysis can download a PDB but fail to save its converted symbols. SIFTed adds `~/.cache/sifted/volatility3/symbols` as a writable symbol directory, created by the worker as the analyst account. This preserves automatic symbol acquisition on a normal SIFT installation without changing global packages, permissions, or services. Override it with `SIFTED_VOLATILITY_SYMBOLS` when needed. Offline mode uses existing symbols and prohibits downloads. The [symbol onboarding guide](volatility-symbols.md) documents the separate native CLI installation tested later: adding readable matching symbols to the default search path allows bare `vol` commands to work as the analyst account.

## Reproduce the real-memory checks

The Windows fixture comes from [Volatility's own test instructions](https://github.com/volatilityfoundation/volatility3/blob/develop/test/README.md). Tests use a digest-pinned, public Windows XP memory image. Download it outside the repository:

```bash
mkdir -p /tmp/sifted-memory-test
curl -fL https://downloads.volatilityfoundation.org/volatility3/images/win-xp-laptop-2005-06-25.img.gz \
  -o /tmp/sifted-memory-test/windows.img.gz
gzip -dk /tmp/sifted-memory-test/windows.img.gz
sha256sum /tmp/sifted-memory-test/windows.img
SIFTED_TEST_MEMORY_IMAGE=/tmp/sifted-memory-test/windows.img \
  .venv/bin/python -m pytest -q tests/test_live_volatility.py
```

The decompressed image is 512 MiB and has SHA-256 `c4aeeb1b461378eef796944884d1d60adaa99cbae4d035923c144b08deee1e6e`. The compressed download has SHA-256 `4cbdd5725adbb9505c8b3f4a51f0f042bac8dd53bf1dcc4b3bb7c71a6c8a74cd`. Tests use isolated temporary databases, output folders, and writable symbol stores; they do not modify the memory image or execute extracted files.

The suite covers successful kernel identification and automatic symbol acquisition; process enumeration, trees and scanning; handles, loaded modules, command lines and environment; file scanning, registry hives and malware scanning; JSON/table/JSON Lines output; PID filtering; PE extraction; symbol reuse offline; a real auxiliary strings file; symbol-free banner scanning; empty results; real scanner cancellation; and mixed plugin success/failure. It compares process, tree and module results directly with the installed CLI and verifies published artifact hashes. The public image contains 47 processes, including `explorer.exe` at PID 1812.

`tests/test_volatility.py` covers request validation, unknown/deprecated or ambiguous plugin names, required file options, typed values, exact 64-bit integer addresses, unchanged preview/execution arguments, isolated extraction destinations, malformed output with exit code zero, partial failures, auxiliary input changes, changed installations while queued, and complete pagination of nested process results.

These checks establish integration and known outcomes for the installed framework and this Windows image. They do not certify every plugin's forensic algorithm or every operating-system version. Linux testing includes generic scanning and missing-symbol behavior; successful Linux/macOS kernel analysis needs real captures and matching symbol tables.

The browser regression suite checks OS tab isolation, typed options, exact 64-bit addresses and completion through polling. A real Chromium check also runs through the temporary SIFT deployment using the normal `./sifted` launcher, verifies OS-tab selection and typed options, extracts the filtered process with JSON Lines output, completes through polling with the event stream blocked, and opens the resulting table.

The [guided memory workspace](memory-analysis.md) uses these same installed plugins and runtime. `tests/test_live_evidence_workspace.py::test_native_workspace_guided_memory_analysis` exercises image identification, process review, PID-scoped command lines/modules, executable extraction and derived-file navigation through the workspace API. It replaces the earlier single-action workspace smoke check.

## Expanded investigation on a real incident exercise

`tests/test_live_memory_investigation.py` exercises the expanded workflow using the original Citadel DC01 acquisition from DFIR Madness's *The Stolen Szechuan Sauce* case, also used by [CSIRT-MU's memory investigation exercise](https://notebooks.csirt.muni.cz/hands-on/memory/). Download outside the repository:

```bash
mkdir -p /tmp/sifted-memory-investigation
curl -fL https://dfirmadness.com/case001/DC01-memory.zip \
  -o /tmp/sifted-memory-investigation/DC01-memory.zip
sha256sum /tmp/sifted-memory-investigation/DC01-memory.zip
unzip -n /tmp/sifted-memory-investigation/DC01-memory.zip -d /tmp/sifted-memory-investigation
sha256sum /tmp/sifted-memory-investigation/citadeldc01.mem
SIFTED_TEST_INVESTIGATION_IMAGE=/tmp/sifted-memory-investigation/citadeldc01.mem \
  .venv/bin/python -m pytest -q -s tests/test_live_memory_investigation.py
```

The ZIP SHA-256 is `86658d85d8254e8d30dccc4f50d9c2a8b550a101d2e78a6d932316849e37ad80`. The unmodified 2,147,483,648-byte capture SHA-256 is `8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62`; the test requires that digest and checks it again after analysis. Allow several GiB for temporary outputs, including a process-memory dump. Extracted code is never executed.

On the connected SIFT workstation (Volatility 3 2.27.0), the complete test passed in 192 seconds. Verified results include:

- NT 6.3 context, 40 listed processes and selected `explorer.exe` PID 3472.
- Every guided Windows process action: command line, modules, executable extraction, handles, environment, SIDs, privileges, potential injection, loader-list comparison, VADs, region and process-memory capture, and YARA. Memmap uses a scalar PID; other process actions use lists. The supplied DOS-message YARA rule is test configuration and produced 208 matches, not 208 malware detections.
- Both network methods: 7,629 NetStat rows and 19,685 NetScan rows. The complete NetScan output matches a separate direct native invocation; comparison is not limited to the displayed page.
- Image-wide injection/process-view checks, service and hive listings, SYSTEM hive extraction, modules/module scanning, driver dispatch and system-call ownership.
- Shared file identification, hex and strings examination of the captured PE; Bulk Extractor email/URL work on the original memory image; native ClamAV examination using the installed signatures.
- A private test signature for the actual recovered PE establishes ClamAV's detection path: exit 1 is a completed examination with a recorded finding. The public signature scan returned no matches. Neither result establishes whether the recovered process is safe.

Follow-up native checks ran both ASCII and UTF-16LE image scans and verified that the workspace retains their results separately. Pasting the presented ClamAV command into Bash, outside SIFTed's executor, reproduced the private-signature finding with exit code 1.

The acquisition exposes two limits that the workflow now handles explicitly. First, native `file` describes the raw capture as a Windows Event Trace Log; the recorded memory acquisition context takes precedence over this generic guess while preserving the original observation. Second, unfiltered hive extraction encounters a page fault in an NTUSER hive. That attempt retains incomplete results and diagnostics, and none of its files enter derived evidence. Guided extraction instead selects a full hive name from a verified listing; the SYSTEM recovery succeeds. Recovery success does not imply every original hive cell was resident.

The XP workspace regression also passes, including an explicit check that unsupported Windows network actions are explained rather than offered as usable. Linux/macOS action names and types match the installed catalog and have deterministic contract coverage; successful kernel analysis on real Linux/macOS captures remains unverified. See the [research note](memory-investigation-research.md) for interpretation guidance and tool-selection sources.
