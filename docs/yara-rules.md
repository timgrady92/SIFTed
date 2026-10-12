# Bundled YARA rules

The guided memory workflow and standalone Volatility examiner prefill the absolute path to `rules/yara/memory.yar` in the running SIFTed checkout. Analysts can run immediately or replace the path with a custom file. Windows and Linux scan mapped process memory; the macOS indicator action scans image bytes with the generic plugin. Existing native plugin discovery still determines availability.

The library ships with the repository and ordinary deployment. There is no startup fetch, package installer, separate scanner or background updater. Volatility uses the YARA engine already installed in its own environment.

## Source review

The [library manifest and source table](../rules/yara/README.md) describe 72 rules selected from Google GCTI, Mandiant and ESET. Review favored attributable research, explicit redistribution terms, specific malware/tool patterns and compatibility with Volatility's byte scans. This is a curated starter set rather than an import of entire repositories or a claim of complete threat coverage.

The selected rules have no includes, scanner-provided external variables, module imports, file-header checks, fixed file offsets or file-size conditions. Those assumptions often belong to file scanning and can silently defeat a mapped-memory scan. Upstream authors, identifiers and descriptions remain intact. A candidate ESET rule for SQL Server routines targeted by Skip-2.0 was excluded because finding the legitimate routine would not identify the implant.

Google's [GCTI repository](https://github.com/chronicle/GCTI) and Mandiant's [countermeasure repository](https://github.com/mandiant/red_team_tool_countermeasures) were archived in May 2025. They supply historical detections for known tools. [ESET's research repository](https://github.com/eset/malware-ioc) supplies the selected Linux/macOS patterns; the age and scope of individual rules still matter. None of these sources promises coverage of every variant or absence of false positives.

Other useful primary collections were evaluated but are not included:

| Collection | Assessment for this default |
| --- | --- |
| [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT-licensed, substantial file-oriented coverage. Reviewed candidates use executable-format constraints; better suited to a future file-scanning library with separate validation. |
| [Elastic protections artifacts](https://github.com/elastic/protections-artifacts) | Valuable detection research, with Elastic License 2.0 terms and engine/scope considerations requiring their own integration review. |
| [Signature-Base](https://github.com/Neo23x0/signature-base) | Broad coverage, but some rules need external scanner variables. DRL 1.1 and per-file exceptions require careful attribution handling, including attribution in match-derived messages; the current native Volatility result does not supply that automatically. |

## Execution and provenance

The exact packaged file is an application resource; its directory does not become an evidence input root. At plan creation, SIFTed verifies the bundle and license hashes, then snapshots the rules, manifest and licenses through the shared `Plan.configs` mechanism. The normal worker saves these under `_sifted/yara/` and includes them in its output manifest. Queued work retains its original rules if the application library is subsequently updated.

The result's collapsed **YARA rules** disclosure identifies the version and sources and links the exact rules used and their manifest. Custom rule files continue through the normal allowed-input-root and auxiliary-file integrity checks. Inline patterns and compiled rules remain available in the standalone examiner; choosing one supersedes the prefilled library. Submitting competing explicit rule sources is rejected.

The educational terminal example uses the original absolute library path with ordinary `vol --yara-file` arguments. It does not expose the worker's temporary directory or require SIFTed to be running. For later reproduction after a library update, use the saved `_sifted/yara/memory.yar` copy.

## Reproduction and maintenance

Run `python3 scripts/build_yara_bundle.py --check` from the repository root to verify all vendored source/license digests and reproduce the exact bundle bytes. `--fetch --check` retrieves only the manifest's pinned revisions and verifies the same hashes. No upstream scripts run.

To update the library, review the proposed source revision, rule semantics, dependencies and licensing; update the explicit file/rule inventory and source/license hashes in `manifest.json`, bump its version/review date, and rebuild with `python3 scripts/build_yara_bundle.py`. Preserve original rule files and notices. Then repeat the native compile, memory scan and regression checks before shipping. Do not treat a successful compilation as evidence of detection quality.

## Validation

On the connected SIFT workstation, the library is checked against classic YARA 4.5.4 and the installed YARA-X engine in Volatility 3 2.27.0's environment. Classic YARA compiles with warnings treated as errors. YARA-X's one accepted style diagnostic suggests spelling an upstream hex literal as text (`text_as_hex`); the rule is retained unchanged. Other warnings fail validation.

The native tests passed on SIFT: system `ls`, Python, SSH and sshd binaries produced no matches, and the original 2 GiB Citadel DC01 capture from the [documented incident exercise](volatility-validation.md#expanded-investigation-on-a-real-incident-exercise) produced zero matches in both the managed all-process scan and pasted native CLI. Both scans reported that PID 3644 had no VADs to scan; that process's mapped memory was unavailable. The managed run preserved the evidence hash and retained the exact rules and source metadata. Results paths contain spaces, and the library is outside permitted evidence roots. Tests use isolated case state and never execute recovered malware.

```bash
SIFTED_TEST_INVESTIGATION_IMAGE=/cases/demo/memory/citadeldc01.mem \
  .venv/bin/python -m pytest -q -s tests/test_live_yara_rules.py
```

Deterministic tests cover damaged resources, license/manifest integrity, updates while queued, custom-file mutation, competing sources, all three OS defaults, and saved provenance. Chromium tests cover guided and standalone defaults, custom/inline overrides, collapsed provenance and phone/desktop layout. An isolated server on SIFT also passed both 390- and 1440-pixel browser checks for the real run's saved rule/manifest links, default paths and repeat-scan preview. Native Linux/macOS capture coverage and broad positive/negative malware corpora remain outside this validation; no detection-rate claim is made.
