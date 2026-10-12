# Memory indicators

SIFTed ships `memory.yar` as the default for its Volatility YARA examinations. This reviewed starter library contains **72 rules from 19 files**. It needs no download at analysis time and no extra workstation packages.

| Source | Selection | Rules | License |
| --- | --- | ---: | --- |
| [Google GCTI](https://github.com/chronicle/GCTI/tree/1c5fd42b1895098527fde00c2d9757edf6b303bb) | Memory-enabled Cobalt Strike Beacon, loader/stager patterns and Sliver | 64 | [Apache-2.0](licenses/google-gcti.txt) |
| [Mandiant](https://github.com/mandiant/red_team_tool_countermeasures/tree/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b) | Production GoRat memory rule, authored by FireEye | 1 | [BSD-2-Clause](licenses/mandiant.txt) |
| [ESET](https://github.com/eset/malware-ioc/tree/705ead5a0a86fefae3c2390f91a339852384f438) | Kobalos, Rakos, Windigo/Onimiki and Keydnap byte/string patterns | 7 | [BSD-2-Clause](licenses/eset.txt) |

Google GCTI and Mandiant's countermeasure repositories are archived. These are known-pattern references, not a continuously updated threat feed. The ESET selections have no file-header, fixed-offset or file-size requirements, but their effectiveness in mapped memory depends on the captured bytes. A match is an investigative lead; an empty scan does not establish that an image is clean. Cobalt Strike and Sliver may also appear in authorized security work.

`manifest.json` records the exact commits, original paths, rule identifiers, licenses and SHA-256 values. `upstream/` holds unchanged original files. The flat bundle preserves rule bodies, authors and identifiers, adds source comments, and normalizes line endings. The listed third-party licenses apply to these resources independently of SIFTed's own license.

From the repository root:

```bash
python3 scripts/build_yara_bundle.py --check
```

To retrieve the same pinned resources and verify the bundle:

```bash
python3 scripts/build_yara_bundle.py --fetch --check
```

Neither command selects newer commits. Library changes require review and an updated manifest. See [selection, integration and validation](../../docs/yara-rules.md).
