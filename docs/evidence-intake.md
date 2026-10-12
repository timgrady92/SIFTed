# Evidence intake

Create a case, then **Add evidence**. Choose a workstation file/directory or upload files from the browser. Record the analyst and, when known, the acquisition source, notes, and expected SHA-256. Every intake enters the durable worker queue. Evidence becomes available for analysis after stable hashing and content profiling succeed.

The Tools entry points use the same verification and profiling services. A new workstation path submitted with a case creates its evidence record transactionally with the run. Existing evidence always keeps its original baseline. Runs without a case retain the same integrity/profile provenance in their run record, but have no case custody ledger.

## Transfers

Browser transfers use bounded 4 MiB requests, exclusive per-transfer locks, fsync, declared size limits, and safe server-assigned destinations under `<first input root>/.sifted-evidence/<transfer id>/files`. Evidence names are preserved. Uploaded files become read-only before intake. A transfer is not evidence-ready simply because its bytes arrived.

Retrying from the same browser with the same selection and acquisition details reuses the transfer. Received chunks are replayed and compared byte for byte before the remaining bytes are appended. Filename, size, and browser timestamps do not establish identity. Interrupted requests can safely overlap the last persisted chunk; conflicting bytes fail. Completed-transfer requests return the original intake job rather than creating duplicates.

For split images, upload every segment and choose the first as the primary file. A primary file collection must include exactly the native segment/companion set. For unrelated files, choose **Collected directory**. The workstation path option also supports nested directories and empty directories. Symlinks and special files are rejected.

`SIFTED_MAX_EVIDENCE_UPLOAD_BYTES` limits the combined declared bytes per transfer (default 1 TiB). This is separate from tool output budgets. Available filesystem space still limits transfers; interrupted files can be retried or discarded through `DELETE /api/case/<case>/uploads/<transfer>` before completion.

## Integrity

Individual files use SHA-256 over their complete bytes. Open-file and path identities are checked before and after hashing. Queue snapshots, related input membership, and source identities are rechecked during execution. Expected acquisition hashes are checked before accepting an initial baseline, including on retries. A failed verification cannot silently replace the original hash.

Directories record every relative file path, byte count, SHA-256, and empty/nonempty directory path. The directory baseline is SHA-256 of this canonical ASCII JSON (sorted keys, ASCII escaping, no whitespace; entries sorted by `path`):

```json
{"entries":[{"kind":"directory","path":"empty"},{"kind":"file","path":"note.txt","sha256":"…","size_bytes":123}],"format":"sifted-manifest-v1"}
```

For a file collection, the displayed baseline identifies the primary file; the manifest records independent hashes for its companions. Conventional split raw/EWF segments, registry logs, and SQLite sidecars are explicit dependencies for every tool. Changes to bytes or membership fail verification. Segment naming establishes collection membership, never file format.

## Profiles and custody

The content profiler combines bounded structure/signature checks with the workstation's `file`/libmagic MIME identification. It records its profile version, method, executable hashes, observations, and the identity of the verified input. Extensions do not establish evidence type. Compound files are inspected with [olefile](https://olefile.readthedocs.io/en/latest/Howto.html) in a subprocess with memory/CPU/time limits. This library is pinned inside SIFTed's virtual environment; no workstation tools or global Python packages need changing. Automatic Jump Lists require a structured DestList stream and, for nonempty lists, a shortcut stream; generic compound documents remain compound documents. Raw disk and memory captures may remain unidentified or receive an incidental generic libmagic classification. Analyst acquisition context takes precedence over these generic guesses, while explicit format checks take precedence over the selected type. Classification is a separate, recorded decision and never rewrites the observed profile. Native adapters remain responsible for full format validation.

After hashing, profile version 2 runs applicable native acquisition probes in the same worker. The shared process supervisor enforces cancellation, deadlines, output limits and crash recovery; reports are published under `_sifted/profiling` and observations enter the custody record. Disk probes run with SIFT's system Python and installed `pytsk3`/`pyewf`. The image reader exposes only the already verified segment list. Memory probes run with the Python behind the installed Volatility console script, in offline mode without downloading symbols. Windows page-table candidates must translate consistent Windows shared-system data before they can establish a raw memory workflow. Native crash-dump and LiME container parsing can establish physical-memory context; an ELF core alone cannot establish a whole-system memory acquisition.

File extensions can prioritize probes but never establish a type or prevent the other eligible probes from running. Generic MIME observations remain recorded even when native structures establish a different workflow. Matching disk and memory results are retained as a conflict. Unavailable libraries, nonzero exits, malformed reports and time limits are recorded separately from a completed probe that found no match. Memory probing starts at 1 MiB unless a memory-container signature is already present; disk probing starts at 512 bytes. Each helper has a 1 GiB address-space and 20-second CPU limit, with worker wall-clock limits of 25 seconds for memory and 10 seconds for disk, plus a 64 KiB report limit. These are bounded recommendations, not guarantees that every page or filesystem is intact.

A supported profile is reused for subsequent analysis and integrity verification when its version, source identity and verified SHA-256 still match. Unresolved profiles are retried on **Verify integrity**, which also upgrades older profile versions. Reading an evidence card never launches an acquisition probe. Captured-file display uses the bounded content profiler; native assessment happens through worker verification when that file is analyzed.

Recognized acquisitions open their workflow automatically. A detected Windows OS is the default, with its selector inside **Analysis settings**. Ordinary files open their examinations directly, with **Choose another workflow** available as a disclosure for ambiguous acquisition context. Only unidentified or conflicting evidence presents **Set type**. Manual choices remain separate custody events and can be changed under **Overview → Manage evidence**. The original SHA-256 and recorded MIME observation remain intact.

Automatic raw-memory recognition currently validates Windows mappings. Raw Linux/macOS memory without a recognized container or suitable structural evidence can remain unresolved. Native disk probing uses the sector geometry supported by the installed Python bindings; signature candidates remain usable when native confirmation cannot complete. No forensic binaries or native Python packages are installed by SIFTed.

The overview shows the baseline, profile, verification state, and downloadable custody/manifest JSON. **Verify integrity** queues a new verification against the existing baseline. **Retire evidence** removes it from active casework while retaining its source, runs, and custody history.

Custody events record intake requests, verification results, classification changes, analysis outcomes, output hashes, and retirement. Captured-file examinations link back to the original evidence through the producing run. Events are appended transactionally, and database triggers reject updates/deletions through the application. Each event's digest is SHA-256 of its canonical JSON excluding `digest`; its `previous` field contains the preceding event digest. Exports include the event count and final digest. Keep exports outside the workstation for subsequent comparison.

The ledger records SIFTed's observations, not historical transfers it did not witness. Analyst names are supplied by the operator; the application does not authenticate them. A database administrator can replace the database, so the ledger is not an independently authenticated or tamper-proof custody system.

## Validation

`tests/test_evidence_intake.py` exercises queued admission, expected-hash rejection/retry, stable hashing, directory and segment baselines, misleading names, renamed forensic artifacts, custody chains, cancellation/recovery, and resumable uploads. Browser tests cover workstation registration, uploads, automatic memory routing and progressive disclosure on desktop/phone layouts. `tests/test_evidence_assessment.py` covers native decisions, conflicting probes, unavailable capabilities, cancellation, profile reuse and misleading extensions. `tests/test_live_evidence_assessment.py` checks the real Citadel capture through workstation intake, an extensionless copy, and a browser upload named `misleading.jpg`. `tests/test_demo_evidence.py` checks unmodified [public samples](../demos/README.md) through upload and workstation intake, including identification after renaming, native parser findings, and fragmented-photo recovery from the E01. `tests/test_live_evidence_workspace.py` also covers the tabbed disk and memory workflows. All validation uses isolated cases; no samples are automatically registered in the running application.
