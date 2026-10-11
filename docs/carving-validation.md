# File carving validation

Validated on the connected SIFT workstation on 2026-10-11, using its existing `/usr/bin/foremost` 1.5.7 (Ubuntu package 1.5.7-11) and `/usr/bin/scalpel` 1.60 (1.60+git20240110.6960eb2-1build1). No system packages, installed signatures, or existing workstation services were changed. Runs used a private checkout, database, and temporary evidence/output roots, including paths with spaces and quotes. `./sifted` provides the same deployment as the other workflows; no additional carving setup is required.

## Correctness changes

Foremost's installed config explicitly says its examples supplement built-in parsers. The previous adapter enabled those commented examples in addition to native parsers. This selected unrelated or obsolete signatures and depended on machine-local configuration. The replacement supplies a comment-only config and explicit native `-t` selectors. The arbitrary ten-second-per-type mode was removed; normal job and process budgets govern the one managed native scan.

The SIFT Scalpel config ships with disabled signatures, including an obsolete PNG footer, an incorrect ZIP footer, and reverse JPG/PDF searches that can combine adjacent files. SIFTed now ships reviewed, versioned profiles. PNG includes its full signature and IEND chunk; ZIP includes the fixed end-of-central-directory record. Forward matching keeps adjacent ordinary files separate. An administrator can supply an active custom Scalpel 1.60 config using `SIFTED_SCALPEL_CONFIG`. Comments are never activated. Invalid escapes and native size/rule limits are checked before execution, preventing malformed signatures from hanging Scalpel's decoder. A single wildcard directive must precede rules, and explicit `FORWARD`, `REVERSE`, `NEXT`, and footerless rules are supported. Extensionless `NONE` rules require flat output: the native grouped mode creates a non-UTF-8 directory and is rejected before execution. Each run persists its selected config and SHA-256.

Carvers require a complete raw stream. Known EWF/AFF/virtual-disk containers and gzip inputs are rejected, including misleading extensions; split raw inputs must be combined. The earlier E01 claim was incorrect: neither native executable decodes EWF. Use a raw export (for example from installed `ewfexport`) before carving. This validation does not certify every possible container signature. Any raw stream may be examined, including complete same-case derived outputs from the disk-analysis workflows.

A successful run requires a complete, single-source native audit. Each recovered file must appear exactly once, have a valid in-bounds range, and contain precisely the audited bytes from the source. Scalpel's exact audit lengths are checked. Foremost's audit rounds displayed sizes; verified file sizes provide exact lengths. `carved.csv` records the relative file path, type, byte offset, exact byte length, SHA-256, chopping indication and native comments. The original audit, configurations, tool output, provenance and hash manifest remain available. The shared publisher rejects non-UTF-8 output paths before renaming or database insertion, retains the complete attempt, and records a terminal error; a malformed native output cannot strand the worker. The analysis table offers follow-up tools using existing derived-artifact baseline checks.

## Fixtures and checks

`tests/carving_samples.py` constructs deterministic raw images from the repository's existing JPEG and generated valid PNG, GIF, PDF, ZIP, BMP and minimal PE fixtures. The ordinary mixed image contains five formats and two additional PNGs whose headers occupy the same 512-byte filename block. Expected bytes and offsets are specified independently of tool output. Files are contiguous; they are not claims of fragmented-file recovery.

`tests/test_live_carving.py` checks:

- Exact bytes, offsets, hashes and seven distinct mixed-image recoveries in Foremost normal/verbose and Scalpel grouped/flat modes. A separate direct CLI invocation must produce identical files using the persisted config.
- Individual format recovery in Foremost for JPEG, PNG, GIF, PDF, ZIP, BMP and PE; acceptance of every exposed native selector. `rif` is accepted by the installed binary; the documented `riff` spelling exits without an audit and is not exposed.
- Native audits in the corrected table viewer, paged recovery analysis and API result links.
- Empty files and zero-filled images as complete zero-recovery scans; missing JPEG footers as unrecovered truncated input.
- Foremost boundary-only scanning: the aligned PNG is recovered while an unaligned PNG is missed; the analysis explicitly records the restricted scan.
- Faithful custom Scalpel wildcard, case-insensitive signatures, forward/reverse/next semantics, and footerless chopped ranges, including flat extensionless output.
- Actual native-process cancellation, process termination and incomplete retained captures; native-step timeouts; output-budget failures.
- Carved PDFs entering same-case `pdftotext` analysis using the producing run's baseline SHA-256; altered derived evidence fails before execution.
- Small PNGs at image EOF compared to the native CLI, exposing Foremost's minimum-buffer heuristic rather than inventing recovery guarantees.
- Optional digest-pinned public Word document comparisons for both DOC and OLE, retaining exactly the native tool's outcome and audit.

`tests/test_carving.py` exercises failed recovery contracts independently of native binaries: zero exit with malformed/incomplete audits, wrong source/offset/length/bytes/count, missing/duplicate/unreported files, symlinks, invalid selections, container/split input rejection, and immutable, faithful configuration snapshots. Browser tests exercise both pages, queueing, polling after losing the event stream, recovery tables and a baseline-verified follow-up examination. Separate Chromium checks exercise the actual `./sifted` deployment on SIFT through a local SSH tunnel.

The final affected suite passed **222 tests on SIFT**, covering carving, native disk tools, shared runtime, application routes, viewers and integrated tools. The local affected suite passed **170 tests**, including all five Chromium checks. The shared runtime also verifies that an invalid UTF-8 output filename preserves the attempt, records a terminal error and allows the worker to execute the next job. Python lint, JavaScript syntax and whitespace checks passed.

## Reproduction

Run from the repository's configured Python environment:

```sh
python -m pytest -q tests/test_carving.py tests/test_live_carving.py
python -m pytest -q tests/test_browser.py -k carving
```

Native execution checks skip when required executables are absent; public Word comparisons additionally require the optional fixture. Cancellation creates temporary sparse 1 GiB images, and timeout checks use temporary sparse 4 GiB images; they are removed after the checks. Images are hashed through the shared worker, so these checks require CPU/I/O time even though sparse files take little physical disk space.

The optional Word fixture is Apache POI's [`test-data/document/simple.doc`](https://github.com/apache/poi/blob/trunk/test-data/document/simple.doc), 19,456 bytes. Download it separately; tests never fetch evidence or tools:

```sh
curl -fsSL https://raw.githubusercontent.com/apache/poi/trunk/test-data/document/simple.doc -o /tmp/sifted-word-simple.doc
sha256sum /tmp/sifted-word-simple.doc
SIFTED_TEST_WORD_DOCUMENT=/tmp/sifted-word-simple.doc python -m pytest -q tests/test_live_carving.py
```

Expected SHA-256: `4876e828e62d490fa188c7c4e47013e2e0dfdf02f5903dfd374bc0d2b2049ca1`.

## Observed limits

The tested Foremost build recovered **zero files** from the public Word fixture in both DOC and OLE modes, including independent CLI checks. A generated CFB container was also missed. Successful selector acceptance is not proof that a parser recovers all valid documents. Small valid PNGs at EOF with fewer than 100 remaining bytes were missed by Foremost; Scalpel recovered the complete PNG. A completed scan means native execution and output validation completed; it does not establish exhaustive recovery, absence of evidence, deletion status, filesystem allocation, original names or original-file completeness.

Scalpel performs header/footer matching, not internal-format parsing. Its defaults cannot guarantee complete JPEGs containing thumbnail EOI markers, incremental PDFs, ZIP comments/ZIP64, fragmentation, or files exceeding profile size limits (20,000,000 bytes per default rule). PDF defaults support LF and CRLF EOF endings. Custom signatures require independent evidence validation; footerless output can include padding and is identified as chopped. Foremost's built-in parsers also have heuristic size/dimension limits. Use multiple recovery methods when examining those cases rather than equating a completed job with exhaustive recovery.

The validated positive formats and inputs are listed above. The remaining Foremost selectors received command-interface and zero-hit checks; this is not certification of every supported format or arbitrary damaged evidence. PhotoRec is installed on SIFT but is not a registered application workflow in either the existing carving implementation or this change.

Primary references: [Foremost's configuration and built-in-parser guidance](https://github.com/gerryamurphy/Foremost/blob/master/foremost.conf), [Scalpel 1.60 source and configuration grammar](https://github.com/nolaforensix/scalpel-1.60), and [upstream corrected Scalpel patterns](https://github.com/sleuthkit/scalpel/blob/master/scalpel.conf). Native outputs and exact-byte comparisons determine the behavior recorded here.
