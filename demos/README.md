# Public demonstration evidence

Seven unmodified public artifacts are bundled in `evidence/` (32.4 MiB total). They are independent acquisitions, not a reconstructed incident. Every file has its upstream URL, size, SHA-256 and expected content type in [manifest.json](manifest.json). No demonstration evidence is loaded into cases automatically.

## Start an exercise

From the repository root, verify the supplied files:

```bash
cd demos/evidence
sha256sum -c ../SHA256SUMS
```

In SIFTed, create a case and choose **Add evidence → Upload files**. Select one sample, enter your name and its expected SHA-256 from the manifest, and upload. The overview should show verified evidence, its content profile, and a custody export before analysis. Use separate evidence items for these independent acquisitions. Uploading several unrelated files as a **Collected directory** instead records one collection with individual file hashes.

To practice with files already on the workstation, copy the samples into a fresh directory under your configured input root. From `demos/evidence`, this creates `/cases/sifted-demo` and refuses to replace an existing directory:

```bash
mkdir /cases/sifted-demo && cp -a --no-clobber . /cases/sifted-demo/
```

Choose **Add evidence → Workstation path**, then browse to an individual file. Store analysis results outside this source directory. Both intake choices use the same verification, profiling and custody framework.

## Exercises and checked findings

| Evidence | What to investigate | Checked finding |
| --- | --- | --- |
| `camera/nps-2009-canon2-gen6.E01` | Map the partition, browse allocated/deleted entries, recover photographs and compare filesystem recovery with carving. | FAT16 starts at sector **51**, using 512-byte sectors. `IMG_0044.JPG` at metadata address **1029** spans three extents; recovered SHA-1 is `916a88a00c58b7a566711acd25e61d549df5d303`. Deleted entries include `_MG_0025.JPG`, `_MG_0030.JPG`, `_MG_0035.JPG`. |
| `windows/Amcache.hve` | Inspect Windows application inventory with AmcacheParser. | 166 exported records; `7z1900-x64.exe` has SHA-1 `9fa11a63b43f83980e0b48dc9ba2cb59d545a4e8`. Inventory alone does not establish execution. |
| `windows/System.evtx` | Review service activity with EvtxECmd. | 5,009 events. First exported event: System / 7036 at `2010-11-21 03:55:59.6264271` UTC. |
| `windows/f01b4d95cf55d32a.automaticDestinations-ms` | Examine Explorer destinations with JLECmd; compare destination paths and embedded shortcuts. | 9 records; entry 7 references `C:\Temp` on `desktop-annfp9d`. Recognized from its streams even when renamed. |
| `windows/NeroInfoTool.lnk` | Examine target path, arguments and timestamps with LECmd. | Target ends in `Nero\Nero 9\Nero InfoTool\InfoTool.exe`; arguments include `-ScParameter=30002`. A shortcut is not proof the target executed. |
| `windows/$I103S5F.jpg` | Parse the deletion record with RBCmd. | Original path `C:\Users\random\Downloads\bunnies.jpg`, size **222,255 bytes**, deleted `2016-06-29 21:37:45.618` UTC. This is deletion metadata, despite its `.jpg` suffix; the photograph itself is absent. |
| `browser/History` | Correlate Chrome searches, visits and executable downloads. | **69 visits**, **55 URLs**, **3 search terms**, and downloads of `funcats_scr.exe` and `Cats Demo.exe` to `/home/john/Downloads/`. These are database records; executable payloads are not included. |

For the browser sample, select **SQLite maps → Windows_ChromiumBrowser_KeywordSearches.smap**. It returns `funny cats`, `really really funny cats`, and `funnycats.exe`. This older Chrome database lacks fields required by newer installed history/download maps. A failed map must not be treated as an empty result; query the original schema with SIFT's `sqlite3` for those records. No workstation maps are modified for this demo.

These commands work directly in the SIFT terminal after the copy above:

```bash
mmls -B /cases/sifted-demo/camera/nps-2009-canon2-gen6.E01
fls -r -o 51 /cases/sifted-demo/camera/nps-2009-canon2-gen6.E01
icat -o 51 /cases/sifted-demo/camera/nps-2009-canon2-gen6.E01 1029 > IMG_0044.JPG
sha1sum IMG_0044.JPG
sqlite3 -readonly -header -column /cases/sifted-demo/browser/History 'SELECT term FROM keyword_search_terms;'
sqlite3 -readonly -header -column /cases/sifted-demo/browser/History "SELECT full_path, datetime(start_time, 'unixepoch') AS started_utc, received_bytes, total_bytes FROM downloads;"
sqlite3 -readonly -header -column /cases/sifted-demo/browser/History "SELECT datetime(visits.visit_time/1000000-11644473600, 'unixepoch') AS visited_utc, urls.url FROM visits JOIN urls ON visits.url=urls.id ORDER BY visits.visit_time;"
```

The camera [narrative](reference/camera-narrative.txt) and [recovery report](reference/camera-report.txt) contain independent ground truth, including fragmentation and hashes. The narrative's heading says FAT32; native partition/filesystem analysis identifies this generation as FAT16. Follow the observed structure. Upstream SHA-1 values identify recovered photographs; SIFTed still records SHA-256 for custody.

## Optional memory acquisition

Volatility's [official test instructions](https://github.com/volatilityfoundation/volatility3/blob/develop/test/README.md) provide a Windows XP laptop capture. It is about 172 MiB compressed and 512 MiB expanded, so it is fetched separately. From a fresh working directory:

```bash
mkdir /cases/sifted-memory-demo
cd /cases/sifted-memory-demo
curl -fL https://downloads.volatilityfoundation.org/volatility3/images/win-xp-laptop-2005-06-25.img.gz -o windows.img.gz
echo '4cbdd5725adbb9505c8b3f4a51f0f042bac8dd53bf1dcc4b3bb7c71a6c8a74cd  windows.img.gz' | sha256sum -c - && gzip -dk windows.img.gz
echo 'c4aeeb1b461378eef796944884d1d60adaa99cbae4d035923c144b08deee1e6e  windows.img' | sha256sum -c -
```

Register `windows.img`, retaining that expected SHA-256. Raw memory may not have a recognizable signature; select **Memory dump** as acquisition context in the overview. Run `windows.pslist.PsList` with the workstation's installed Volatility 3: expect **47 processes**, including `explorer.exe` at **PID 1812**. See [memory validation](../docs/volatility-validation.md) for symbol handling and more exercises.

## Sources and redistribution

- **Camera**: [Digital Corpora's NPS disk collection](https://digitalcorpora.org/corpora/disk-images/), released for public forensic research and education. Its NPS-created content is public domain. This camera corpus contains photographs of numbered screens/paper; the original image, narrative and recovery report are unchanged. Attribution: Garfinkel, Farrell, Roussev and Dinolt, *Bringing Science to Digital Forensics with Standardized Forensic Corpora*, DFRWS 2009.
- **Amcache, EVTX, LNK, Recycle Bin, Chrome**: [Plaso](https://github.com/log2timeline/plaso/tree/0f122c3878bdac3ff716b56f23988885675fea28), commit `0f122c3878bdac3ff716b56f23988885675fea28`. The project's [copyright declaration](licenses/plaso-copyright.txt) covers its files under [Apache 2.0](licenses/plaso-Apache-2.0.txt); copyright The Plaso project authors. Original bytes are retained. Directory nesting is simplified, and `win10-Amcache.hve` is named `Amcache.hve` here. Exact source URLs are in the manifest.
- **Jump List**: [Eric Zimmerman's JumpList](https://github.com/EricZimmerman/JumpList/tree/e87bacd4869cbe0633c16ad11d3d26c9f39d0a2b), commit `e87bacd4869cbe0633c16ad11d3d26c9f39d0a2b`, under its included [MIT license](licenses/JumpList-MIT.txt).
- **Memory**: linked to its original host; it is not redistributed in this repository.

## Validation

`tests/test_demo_evidence.py` verifies every bundled hash, uploads and registers every sample with an uninformative filename, and checks identical content profiles and custody chains. On SIFT it also runs installed parsers against known records and recovers the fragmented camera photograph through the managed worker. Native cases, transfers and results live in temporary test directories. Unit fixtures elsewhere exercise malformed input and failure handling; they are not demonstration evidence.
