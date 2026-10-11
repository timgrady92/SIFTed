# Tool integration

SIFTed discovers installed executables through `PATH` and administrator-provided `SIFTED_BINARIES` prefixes. The workstation's complete tool inventory is independent of the workflows supported by the app.

| Workflow | Executables | Output |
| --- | --- | --- |
| Strings | `strings` | Offset-aware text |
| Metadata | `exiftool` | CSV or JSON |
| File identification | `file` | CSV with MIME mismatches |
| Carving | `foremost`, `scalpel` | Recovered files, original audits, and source-range-verified `carved.csv` |
| Feature extraction | `bulk_extractor` | Feature files and reports |
| Timeline | `log2timeline.py`, `psort.py` | Plaso storage and CSV |
| Memory analysis | `vol` (Volatility 3) | Per-plugin JSON, JSON Lines or text, isolated extracted files |
| Windows artifacts | `dotnet` and Zimmerman assemblies; SIFTed SQLite map executor | Validated native CSVs, plugin tables and per-input/query outcomes |

The Zimmerman catalog is defined in `sifted_core/catalog.py`; `zimmerman.py` owns parser-specific contracts and direct assembly discovery. Registry analysis uses verified private hive/log captures with replay enabled by default. RECmd exposes installed batch profiles; EvtxECmd and SQLite workflows freeze installed maps. Directory inputs receive separate export scopes, native diagnostics and complete CSV validation. SQLECmd maps run through SIFTed's read-only Python SQLite executor because the tested SIFT native binary cannot execute queries on Linux. The UI clearly names this engine. See [Zimmerman validation](zimmerman-validation.md) for native versions, fixture provenance, query semantics and limitations.

Foremost uses explicit native built-in selectors and an empty custom-signature snapshot, so unrelated host signatures cannot extend the selected scope. Scalpel uses versioned, reviewed profiles for JPG, PNG, GIF, PDF and ZIP; `SIFTED_SCALPEL_CONFIG` can select an administrator-maintained Scalpel 1.60 profile. Only active rules are selectable; comments remain disabled, and wildcard/search-direction settings are preserved. Selections use canonical names (including Foremost's actual `rif` selector); aliases and the old ten-second safe mode were removed.

Carvers accept complete raw byte streams, including hash-verified `icat`, `blkcat` and `blkls` outputs. EWF and other known image containers, compressed images, and split streams must first be decoded or combined into raw. Native audits must have a complete single-source table, a completion marker, and consistent records. Every captured file must appear exactly once in the audit and match its recorded source byte range; exact lengths and SHA-256 values go into `carved.csv`. Foremost's human-readable audit sizes are rounded, so exact lengths come from the verified files. A completed zero-recovery scan is valid, but does not establish that files are absent. Successful recoveries support same-case, baseline-verified follow-up examination. Failed/cancelled captures stay incomplete. See [carving validation](carving-validation.md) for tested formats and concrete native-tool limitations.

Volatility plugin selections and typed options come from the installed framework. Deprecated plugins are excluded. Each plugin has its own output directory, and required options are checked before queueing. Windows symbols download automatically into a writable user directory; offline mode is explicit. Configure permitted symbol roots for additional Linux/macOS or predownloaded Windows symbols. JSON results are bounded at 64 MiB per plugin; choose JSON Lines for large results. Structured results are validated before success, and `plugin-summary.json` records each plugin’s outcome and row count. Mixed outcomes fail the job while preserving successful and failed plugin captures. Integer options accept decimal/hexadecimal strings to preserve full 64-bit address precision; large integers in lists must be quoted JSON strings. Auxiliary files (such as a strings file or YARA rules) must be under input roots and are hashed and checked like the memory image. Tool installation and a matching command interface do not guarantee that a specific evidence format or operating-system version is supported.

CSV and JSON Lines browsing share a signature-based SQLite page cache; files are indexed once and reindexed when changed. Table imports are limited to 1 GiB, and JSON Lines records to 64 MiB. Nested Volatility rows are flattened with depth recorded, preserving every process in a tree. Each successful plugin also saves its resolved framework configuration, while installation snapshots record CLI and plugin source hashes.

Run `pytest -m live -q` on a workstation to exercise the available tools against isolated synthetic inputs. See [the runtime design](runtime.md) for the adapter contract and the limits of this validation.
