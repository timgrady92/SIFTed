# Volatility 3 symbol onboarding

Open **Guides → Volatility symbol setup**, or the link inside the memory workspace's collapsed CLI/advanced sections. The in-app guide uses the symbol directory discovered from the installed `vol` interpreter, so its installation commands follow that workstation's paths. The commands below are for the connected SIFT installation (Volatility 3 2.27.0, Python 3.12 under `/opt/volatility3`). Recheck the path after upgrading Volatility.

## Windows: download only what your capture needs

Run as the analyst, replacing the example image path if needed:

```bash
mkdir -p -- /home/sansforensics/.local/share/volatility3/symbols
vol -f /cases/demo/memory/windows-xp.img -s /home/sansforensics/.local/share/volatility3/symbols windows.info.Info
```

Volatility identifies the required PDB and downloads it from [Microsoft's public symbol server](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols), then converts it to a JSON symbol table. This preparation needs internet access. Confirm that image identification succeeds before continuing. [Volatility's symbol documentation](https://volatility3.readthedocs.io/en/stable/symbol-tables.html) describes the matching process.

Install the downloaded symbol data into the native default search path. These commands use GNU coreutils on SIFT; existing tables are retained. Only this installation step needs sudo:

```bash
sudo cp -R --update=none -- /home/sansforensics/.local/share/volatility3/symbols/windows /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/
sudo chmod -R a+rX -- /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/windows
```

Verify local symbol discovery, then run the analytical command directly:

```bash
vol -q --offline -f /cases/demo/memory/windows-xp.img windows.info.Info
vol -q -f /cases/demo/memory/windows-xp.img -r jsonl windows.cmdline.CmdLine --pid 1812
```

The connected SIFT workstation passed this procedure with a fresh download directory. The second command returned PID 1812, `explorer.exe`, and `C:\WINDOWS\Explorer.EXE`, without a symbol-directory flag or report redirection. This prepares that Windows kernel; another capture may require different symbols. Network plugins may need additional Windows symbol tables too.

## Offline packs

The [official Volatility README](https://github.com/volatilityfoundation/volatility3#symbol-tables) links these release assets:

- [Windows pack](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/windows.zip)
- [Linux pack](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/linux.zip)
- [macOS pack](https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/mac.zip)
- [SHA-256 checksums](https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS)

Download on a connected machine. From a new working directory:

```bash
curl -fL --output windows.zip https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/windows.zip
curl -fL --output SHA256SUMS https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Proceed only when `windows.zip: OK` is reported. Transfer the verified archive to SIFT if necessary, then install:

```bash
sudo install -m 644 -- windows.zip /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/windows.zip
```

For Linux/macOS packs, substitute `linux.zip` or `mac.zip` in both commands and verify against the same checksum list. Leave the archives zipped and preserve their names. Initial indexing can take time. The packs contain selected builds; they are not exhaustive. This work verified all three download endpoints, downloaded and hash-checked the 3 MB Linux pack, and tested targeted Windows acquisition. The large Windows/macOS packs were not downloaded.

## Linux and macOS

Start with the capture's actual banner:

```bash
vol -f /cases/memory.img banners.Banners
```

The table must match the full build banner. Use the official packs or the [community symbol collection](https://github.com/Abyss-W4tcher/volatility3-symbols) linked by [Volatility's Linux tutorial](https://volatility3.readthedocs.io/en/stable/getting-started-linux-tutorial.html). For individual files, use the selected entry's raw download link and retain its source and hash; no universal URL can select the right kernel for an unknown capture.

If no table matches, obtain that kernel's debug image and generate one with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json). Building dwarf2json requires Go; this guide does not install it or change SIFT's forensic packages. An ordinary stripped kernel is insufficient. With the tool available and matching files under `/cases/kernel`:

```bash
dwarf2json linux --elf /cases/kernel/vmlinux --system-map /cases/kernel/System.map > kernel.json
sudo install -D -m 644 -- kernel.json /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/linux/kernel.json
vol -q --offline -f /cases/memory.img linux.pslist.PsList
```

For macOS:

```bash
dwarf2json mac --macho /cases/kernel/kernel.debug > kernel.json
sudo install -D -m 644 -- kernel.json /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/mac/kernel.json
vol -q --offline -f /cases/memory.img mac.pslist.PsList
```

Use distinct filenames when retaining multiple kernels. These generation examples follow upstream instructions; native Linux/macOS capture validation remains outstanding.

## SIFTed access

SIFTed already downloads Windows symbols into its service account's writable `~/.cache/sifted/volatility3/symbols`, configurable with `SIFTED_VOLATILITY_SYMBOLS`. It reads the native installation's symbol directories too. On the connected workstation, the service runs as `sansforensics`, which owns the managed directory. The native CLI and SIFTed can read the installed tables; neither needs elevated privileges for analysis.

For a different service account or location, create a dedicated symbol directory owned by that account and set `SIFTED_VOLATILITY_SYMBOLS` accordingly. Give it read/write/traversal access there, not ownership of `/opt/volatility3` or its program files. For additional kernel-symbol directories, configure `SIFTED_SYMBOL_ROOTS` and select the directory in the plugin examiner. Those deliberately selected directories remain visible as `-s` in CLI examples.

SIFTed does not run sudo, relax system permissions, install packs, or modify native Volatility automatically. The guide provides explicit one-time workstation administration, separate from the analytical snippets.
