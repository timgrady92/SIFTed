# Forensic Tools Inventory

A comprehensive list of forensic tools available on this SIFT workstation, organized by category.

---

## Disk/Image Acquisition & Handling

| Tool | Path | Description |
|------|------|-------------|
| dc3dd | `/usr/bin/dc3dd` | Enhanced dd with on-the-fly hashing |
| dcfldd | `/usr/bin/dcfldd` | Forensic dd with hashing and verification |
| ewfacquire | `/usr/bin/ewfacquire` | Create E01 forensic images |
| ewfacquirestream | `/usr/bin/ewfacquirestream` | Stream-based E01 acquisition |
| ewfexport | `/usr/bin/ewfexport` | Export E01 images to raw format |
| ewfinfo | `/usr/bin/ewfinfo` | Display E01 image metadata |
| ewfverify | `/usr/bin/ewfverify` | Verify E01 image integrity |
| ewfmount | `/usr/bin/ewfmount` | Mount E01 images as virtual devices |
| ewfrecover | `/usr/bin/ewfrecover` | Recover corrupted E01 images |
| ewfdebug | `/usr/bin/ewfdebug` | Debug E01 image issues |
| affcat | `/usr/bin/affcat` | Output AFF file contents |
| affcompare | `/usr/bin/affcompare` | Compare AFF files |
| affconvert | `/usr/bin/affconvert` | Convert between AFF formats |
| affcopy | `/usr/bin/affcopy` | Copy AFF files |
| affcrypto | `/usr/bin/affcrypto` | AFF encryption operations |
| affdiskprint | `/usr/bin/affdiskprint` | Print AFF disk information |
| affinfo | `/usr/bin/affinfo` | Display AFF file metadata |
| affix | `/usr/bin/affix` | Fix corrupted AFF files |
| affrecover | `/usr/bin/affrecover` | Recover AFF files |
| affsegment | `/usr/bin/affsegment` | AFF segment operations |
| affsign | `/usr/bin/affsign` | Sign AFF files |
| affstats | `/usr/bin/affstats` | AFF file statistics |
| affuse | `/usr/bin/affuse` | FUSE mount for AFF files |
| affverify | `/usr/bin/affverify` | Verify AFF file integrity |
| affxml | `/usr/bin/affxml` | Export AFF metadata as XML |
| imagemounter | `/opt/imagemounter` | Forensic image mounting utility |

---

## The Sleuth Kit (File System Analysis)

| Tool | Path | Description |
|------|------|-------------|
| autopsy | `/snap/bin/autopsy` | GUI forensic browser (v4.22.1) |
| fls | `/usr/bin/fls` | List files and directories in an image |
| icat | `/usr/bin/icat` | Extract file content by inode number |
| istat | `/usr/bin/istat` | Display inode metadata and details |
| ils | `/usr/bin/ils` | List inode information |
| ifind | `/usr/bin/ifind` | Find inode for a given file path |
| ffind | `/usr/bin/ffind` | Find filename for a given inode |
| mmls | `/usr/bin/mmls` | Display partition table layout |
| mmcat | `/usr/bin/mmcat` | Extract partition data |
| mmstat | `/usr/bin/mmstat` | Partition table statistics |
| fsstat | `/usr/bin/fsstat` | Display file system details |
| blkcalc | `/usr/bin/blkcalc` | Block address calculations |
| blkcat | `/usr/bin/blkcat` | Extract block content |
| blkls | `/usr/bin/blkls` | List block details |
| blkstat | `/usr/bin/blkstat` | Display block statistics |
| img_cat | `/usr/bin/img_cat` | Output image file contents |
| img_stat | `/usr/bin/img_stat` | Display image file details |
| mactime | `/usr/bin/mactime` | Create timeline from bodyfile |
| tsk_recover | `/usr/bin/tsk_recover` | Recover deleted files |
| tsk_loaddb | `/usr/bin/tsk_loaddb` | Load image into SQLite database |
| tsk_comparedir | `/usr/bin/tsk_comparedir` | Compare directory contents |
| tsk_gettimes | `/usr/bin/tsk_gettimes` | Extract timestamps |
| tsk_imageinfo | `/usr/bin/tsk_imageinfo` | Display image information |
| sorter | `/usr/bin/sorter` | Sort files by type/category |
| sigfind | `/usr/bin/sigfind` | Find file signatures in raw data |
| hfind | `/usr/bin/hfind` | Hash database lookups |

---

## Timeline Analysis (Plaso)

| Tool | Path | Description |
|------|------|-------------|
| log2timeline.py | `/usr/bin/log2timeline.py` | Create super timelines from artifacts |
| psort.py | `/usr/bin/psort.py` | Process, filter, and output timelines |
| psteal.py | `/usr/bin/psteal.py` | Combined extraction and sorting |

**Python Library:** `plaso` (v20250918)

---

## File Carving & Recovery

| Tool | Path | Description |
|------|------|-------------|
| foremost | `/usr/bin/foremost` | Header-based file carving |
| scalpel | `/usr/bin/scalpel` | Fast, configurable file carving |
| bulk_extractor | `/usr/bin/bulk_extractor` | Extract artifacts (emails, URLs, credit cards, etc.) |
| photorec | `/usr/bin/photorec` | Photo and file recovery |
| testdisk | `/usr/bin/testdisk` | Partition and boot sector recovery |
| binwalk | `/usr/bin/binwalk` | Firmware and embedded file extraction |
| pe-carver | `/opt/pe-carver` | PE executable file carving |
| sqlite-carver | `/opt/sqlite-carver` | SQLite database carving |

---

## Eric Zimmerman Tools

**Location:** `/opt/zimmermantools/`

| Tool | Description |
|------|-------------|
| AmcacheParser | Parse Windows Amcache.hve for program execution |
| AppCompatCacheParser | Parse ShimCache for program execution |
| EvtxeCmd | Windows Event Log (EVTX) parsing and analysis |
| JLECmd | Jump List parsing for recent files/applications |
| LECmd | LNK shortcut file parsing |
| MFTECmd | Master File Table ($MFT) parsing |
| RBCmd | Recycle Bin ($I/$R files) parsing |
| RECmd | Registry explorer command-line tool |
| RecentFileCacheParser | Parse RecentFileCache.bcf |
| SBECmd | ShellBags parsing for folder access history |
| SQLECmd | SQLite database parsing with predefined queries |

---

## Windows Artifact Analysis

| Tool | Path | Description |
|------|------|-------------|
| amcache | `/opt/amcache` | Amcache.hve analysis |
| analyzemft | `/opt/analyzemft` | MFT analysis and parsing |
| indxparse | `/opt/indxparse` | NTFS INDX attribute parsing |
| python-evtx | `/opt/python-evtx` | Windows Event Log (EVTX) parsing |
| usnparser | `/opt/usnparser` | USN Change Journal parsing |
| usbdeviceforensics | `/opt/usbdeviceforensics` | USB device connection history |
| page-brute | `/opt/page-brute` | Windows pagefile analysis |
| java-idx-parser | `/opt/java-idx-parser` | Java cache IDX file parsing |
| samdump2 | system installed | SAM database password extraction |

---

## Registry Analysis

| Tool | Path | Description |
|------|------|-------------|
| RECmd | `/opt/zimmermantools/RECmd/` | Registry explorer CLI |
| AppCompatCacheParser | `/opt/zimmermantools/` | ShimCache from SYSTEM hive |
| AmcacheParser | `/opt/zimmermantools/` | Amcache.hve parsing |

---

## Hashing & Verification

| Tool | Path | Description |
|------|------|-------------|
| hashdeep | `/usr/bin/hashdeep` | Recursive hashing with audit mode |
| md5deep | `/usr/bin/md5deep` | Recursive MD5 hashing |
| sha256deep | `/usr/bin/sha256deep` | Recursive SHA256 hashing |
| ssdeep | `/usr/bin/ssdeep` | Context-triggered piecewise (fuzzy) hashing |

---

## Network Forensics

| Tool | Path | Description |
|------|------|-------------|
| wireshark | `/usr/bin/wireshark` | Packet analysis GUI |
| tcpdump | `/usr/bin/tcpdump` | Command-line packet capture and analysis |
| tcpreplay | `/usr/bin/tcpreplay` | Replay captured pcap files |
| tcpslice | `/usr/bin/tcpslice` | Extract portions of pcap files |
| tcptrace | `/usr/bin/tcptrace` | TCP connection analysis |
| mailsnarf | `/usr/bin/mailsnarf` | Extract email from network traffic |

---

## Malware & Document Analysis

| Tool | Path | Description |
|------|------|-------------|
| yara | python library | Pattern matching for malware classification |
| densityscout | `/usr/local/bin/densityscout` | Entropy-based packed/encrypted file detection |
| pdf-parser.py | `/usr/local/bin/pdf-parser.py` | PDF structure analysis |
| pdf-tools | `/opt/pdf-tools` | PDF forensics toolkit |
| pefile | python library | PE executable file analysis |
| packerid | `/opt/packerid` | Executable packer identification |
| pe-carver | `/opt/pe-carver` | PE file carving from memory/disk |
| pe-scanner | `/opt/pe-scanner` | PE file scanning and analysis |

**Python Libraries:**
- `yara-python` (v4.5.0)
- `pefile` (v2024.8.26)

---

## macOS Forensics

| Tool | Path | Description |
|------|------|-------------|
| mac-apt | `/opt/mac-apt` | macOS Artifact Parsing Tool |

---

## Mobile Forensics

| Tool | Path | Description |
|------|------|-------------|
| mvt | `/opt/mvt` | Mobile Verification Toolkit (iOS/Android) |
| ufade | `/opt/ufade` | iOS forensic artifact extraction |

---

## Browser Forensics

| Tool | Path | Description |
|------|------|-------------|
| pyhindsight | `/opt/pyhindsight` | Chrome/Chromium browser history analysis |

---

## Metadata Extraction

| Tool | Path | Description |
|------|------|-------------|
| exiftool | `/usr/local/bin/exiftool` | Comprehensive metadata extraction |
| exif | `/usr/bin/exif` | EXIF metadata from images |
| exif2map.pl | `/usr/bin/exif2map.pl` | Map EXIF GPS coordinates |
| exifautotran | `/usr/bin/exifautotran` | Auto-rotate images by EXIF |
| jpegexiforient | `/usr/bin/jpegexiforient` | JPEG orientation extraction |

---

## Hex/Binary Analysis

| Tool | Path | Description |
|------|------|-------------|
| xxd | `/usr/bin/xxd` | Hex dump and reverse |
| hexdump | `/usr/bin/hexdump` | Display file in hex format |
| strings | `/usr/bin/strings` | Extract printable strings |
| file | `/usr/bin/file` | Determine file type |
| objdump | `/usr/bin/objdump` | Object file analysis |
| readelf | `/usr/bin/readelf` | ELF file analysis |

---

## Threat Intelligence

| Tool | Path | Description |
|------|------|-------------|
| machinae | `/opt/machinae` | Security intelligence lookups |
| ioc_writer | `/opt/ioc_writer` | IOC (Indicator of Compromise) creation |
| stix-validator | `/opt/stix-validator` | STIX format validation |

---

## Scripting & Automation

| Tool | Path | Description |
|------|------|-------------|
| 4n6-scripts | `/opt/4n6-scripts` | Collection of forensic scripts |

---

## Python Libraries (pip3)

| Package | Version | Description |
|---------|---------|-------------|
| plaso | 20250918 | Timeline analysis framework |
| dfvfs | 20240505 | Virtual file system abstraction |
| artifacts | 20250913 | Forensic artifact definitions |
| yara-python | 4.5.0 | YARA pattern matching |
| pefile | 2024.8.26 | PE file analysis |
| pytsk3 | system | TSK Python bindings |
| python3-binwalk | system | Binwalk Python bindings |

---

## System Packages (apt)

Key forensic packages installed via apt:

- `sleuthkit` - The Sleuth Kit utilities
- `libewf` / `libewf-tools` - E01 format support
- `afflib-tools` - AFF format support
- `plaso-tools` - Timeline analysis
- `bulk-extractor` - Artifact extraction
- `foremost` - File carving
- `scalpel` - File carving
- `binwalk` - Firmware analysis
- `wireshark` - Network analysis
- `tcpdump` - Packet capture
- `hashdeep` - Recursive hashing
- `ssdeep` - Fuzzy hashing
- `dc3dd` / `dcfldd` - Forensic imaging
- `testdisk` - Partition recovery
- `libimage-exiftool-perl` - Metadata extraction

---

## Summary by Category

| Category | Tool Count |
|----------|------------|
| Disk/Image Acquisition | 26 |
| Sleuth Kit (File System) | 27 |
| Timeline Analysis | 3 |
| File Carving & Recovery | 8 |
| Eric Zimmerman Tools | 11 |
| Windows Artifacts | 9 |
| Hashing & Verification | 4 |
| Network Forensics | 6 |
| Malware/Document Analysis | 8 |
| macOS Forensics | 1 |
| Mobile Forensics | 2 |
| Browser Forensics | 1 |
| Metadata Extraction | 5 |
| Hex/Binary Analysis | 6 |
| Threat Intelligence | 3 |
| Python Libraries | 7 |

**Total: 100+ forensic tools**
