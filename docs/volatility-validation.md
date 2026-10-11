# Volatility 3 validation

The connected SIFT workstation supplies `/usr/local/bin/vol`, using `/opt/volatility3/bin/python3` and framework version 2.27.0. This matches [SIFT's standard provisioning state](https://github.com/teamdfir/sift-saltstack/blob/master/sift/python3-packages/volatility3.sls). SIFTed uses that installation through its normal console script; the app virtual environment does not need Volatility. Discovery currently exposes 167 nondeprecated plugins and 191 typed options. The live discovery test checks every plugin and advertised option against the installed CLI help. Installation snapshots include CLI and plugin source hashes; each successful plugin saves its resolved framework configuration beside its results.

The workstation's installed symbol directories are root-owned. A direct Windows analysis can download a PDB but fail to save its converted symbols. SIFTed adds `~/.cache/sifted/volatility3/symbols` as a writable symbol directory, created by the worker as the analyst account. This preserves automatic symbol acquisition on a normal SIFT installation without changing global packages, permissions, or services. Override it with `SIFTED_VOLATILITY_SYMBOLS` when needed. Offline mode uses existing symbols and prohibits downloads.

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
