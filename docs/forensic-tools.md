# Tool integration

SIFTed discovers installed executables through `PATH` and administrator-provided `SIFTED_BINARIES` prefixes. The workstation's complete tool inventory is independent of the workflows supported by the app.

| Workflow | Executables | Output |
| --- | --- | --- |
| Strings | `strings` | Offset-aware text |
| Metadata | `exiftool` | CSV or JSON |
| File identification | `file` | CSV with MIME mismatches |
| Carving | `foremost`, `scalpel` | Recovered files and audit logs |
| Feature extraction | `bulk_extractor` | Feature files and reports |
| Timeline | `log2timeline.py`, `psort.py` | Plaso storage and CSV |
| Memory analysis | `vol`, `vol3`, or `volatility3` | Per-plugin JSON or text |
| Windows artifacts | `dotnet` and Zimmerman assemblies | Parser CSV files |

The Zimmerman catalog is defined in `sifted_core/catalog.py`. Its installation resolver searches `SIFTED_EZ_ROOT` for assemblies and prefers direct `dotnet` invocation over SIFT shell wrappers. RECmd also requires `RECmd/BatchExamples/RegistryASEPs.reb` beneath that root. Foremost and Scalpel use snapshots derived from their configured installed signature files; aliases such as `jpeg` and `tiff` normalize to those files' type names.

Volatility plugin selections come from the configured catalog. It runs offline; configure permitted symbol roots when explicit symbols are required. Tool installation and a matching command interface do not guarantee that a specific evidence format or operating-system version is supported.

Run `pytest -m live -q` on a workstation to exercise the available tools against isolated synthetic inputs. See [the runtime design](runtime.md) for the adapter contract and the limits of this validation.
