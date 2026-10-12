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

The overview shows the baseline, profile, verification state, and downloadable custody/manifest JSON. **Verify integrity** queues a new verification against the existing baseline. **Retire evidence** removes it from active casework while retaining its source, runs, and custody history.

Custody events record intake requests, verification results, classification changes, analysis outcomes, output hashes, and retirement. Captured-file examinations link back to the original evidence through the producing run. Events are appended transactionally, and database triggers reject updates/deletions through the application. Each event's digest is SHA-256 of its canonical JSON excluding `digest`; its `previous` field contains the preceding event digest. Exports include the event count and final digest. Keep exports outside the workstation for subsequent comparison.

The ledger records SIFTed's observations, not historical transfers it did not witness. Analyst names are supplied by the operator; the application does not authenticate them. A database administrator can replace the database, so the ledger is not an independently authenticated or tamper-proof custody system.

## Validation

`tests/test_evidence_intake.py` exercises queued admission, expected-hash rejection/retry, stable hashing, directory and segment baselines, misleading names, renamed forensic artifacts, custody chains, cancellation/recovery, and resumable uploads. Browser tests cover workstation registration and uploading on desktop/phone layouts. `tests/test_demo_evidence.py` checks unmodified [public samples](../demos/README.md) through upload and workstation intake, including identification after renaming, native parser findings, and fragmented-photo recovery from the E01. `tests/test_live_evidence_workspace.py` also covers the tabbed disk and memory workflows. All validation uses isolated cases; no samples are automatically registered in the running application.
