# Test Samples

This directory contains small, synthetic forensic artifact samples for validating tool functionality. Each sample should have **known values** that tests can verify.

## Directory Structure

```
samples/
├── prefetch/       # Windows Prefetch files (.pf)
├── evtx/           # Windows Event Log files (.evtx)
├── registry/       # Windows Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT)
├── lnk/            # Windows shortcut files (.lnk)
├── sqlite/         # SQLite databases (browser history, etc.)
├── mft/            # NTFS Master File Table ($MFT)
├── images/         # Images with EXIF metadata (.jpg, .png)
├── jumplist/       # Windows Jump List files
├── recyclebin/     # Recycle Bin $I files
└── shellbags/      # Registry hives containing ShellBags
```

## Sample Requirements

Each sample must be:
1. **Small** - Minimal file size for fast test execution
2. **Known** - Contains specific values that tests can validate
3. **Documented** - Expected values listed below

## Expected Values by Sample Type

### prefetch/
| File | Expected Tool Output |
|------|---------------------|
| `NOTEPAD.EXE-{hash}.pf` | ExecutableName: NOTEPAD.EXE, RunCount: 5 |

### evtx/
| File | Expected Tool Output |
|------|---------------------|
| `Security.evtx` | Contains Event ID 4624 (logon), User: TESTUSER |
| `System.evtx` | Contains Event ID 7045 (service install) |

### registry/
| File | Expected Tool Output |
|------|---------------------|
| `NTUSER.DAT` | Run key: `C:\malware\evil.exe` |
| `SYSTEM` | Service: `EvilService` |

### lnk/
| File | Expected Tool Output |
|------|---------------------|
| `document.lnk` | TargetPath: `C:\Users\Test\Documents\secret.docx` |

### sqlite/
| File | Expected Tool Output |
|------|---------------------|
| `History` | URL: `https://example.com/test`, Title: `Test Page` |

### mft/
| File | Expected Tool Output |
|------|---------------------|
| `$MFT` | Contains file record for `secret.txt` with known timestamps |

### images/
| File | Expected Tool Output |
|------|---------------------|
| `geotagged.jpg` | GPS: 37.7749, -122.4194 (San Francisco) |
| `camera.jpg` | Make: TestCamera, Model: TC-1000 |

### jumplist/
| File | Expected Tool Output |
|------|---------------------|
| `*.automaticDestinations-ms` | Recent file: `C:\Users\Test\report.xlsx` |

### recyclebin/
| File | Expected Tool Output |
|------|---------------------|
| `$I{id}` | Original path: `C:\Users\Test\deleted.txt` |

### shellbags/
| File | Expected Tool Output |
|------|---------------------|
| `NTUSER.DAT` | Folder access: `C:\Users\Test\Secret Folder` |

## Creating Synthetic Samples

### Images (Easy)
Create a JPEG with known EXIF data using exiftool:
```bash
# Create a minimal image
convert -size 100x100 xc:white tests/samples/images/test.jpg

# Add EXIF metadata
exiftool -GPSLatitude=37.7749 -GPSLongitude=-122.4194 \
         -GPSLatitudeRef=N -GPSLongitudeRef=W \
         -Make="TestCamera" -Model="TC-1000" \
         tests/samples/images/geotagged.jpg
```

### LNK Files (Moderate)
Use pylnk3 or similar library:
```python
import pylnk3
lnk = pylnk3.create("tests/samples/lnk/document.lnk")
lnk.target = r"C:\Users\Test\Documents\secret.docx"
lnk.save()
```

### SQLite Browser History (Moderate)
```python
import sqlite3
conn = sqlite3.connect("tests/samples/sqlite/History")
conn.execute("""CREATE TABLE urls (
    id INTEGER PRIMARY KEY,
    url TEXT,
    title TEXT,
    visit_count INTEGER,
    last_visit_time INTEGER
)""")
conn.execute("""INSERT INTO urls VALUES
    (1, 'https://example.com/test', 'Test Page', 5, 13300000000000000)""")
conn.commit()
```

### Registry Hives (Complex)
Use python-registry or yarp for creating minimal hives, or extract from a test VM.

### Prefetch / EVTX / MFT (Complex)
These formats are complex. Options:
1. Extract minimal samples from NIST CFReDS or Digital Corpora
2. Create in a Windows test VM and copy out
3. Use format-specific libraries if available

## Public Sample Sources

If synthetic creation is too complex, consider samples from:
- **NIST CFReDS**: https://cfreds.nist.gov/
- **Digital Corpora**: https://digitalcorpora.org/
- **SANS SIFT Sample Data**: Included with SIFT Workstation
- **AboutDFIR Sample Files**: https://aboutdfir.com/

Note: When using public samples, document the source and expected values.
