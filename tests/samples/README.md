# Test samples

The repository contains two small JPEG fixtures in `images/`: `test_sample.jpg` and `geotagged.jpg`. The latter carries synthetic camera and GPS metadata. `test_live_tools.py` copies the fixture into isolated evidence directories and verifies metadata extraction and file identification through the application's adapters and worker.

Unmodified public disk, registry, EVTX, Jump List, shortcut, Recycle Bin and browser samples are bundled separately in [demos](../../demos/README.md), with hashes, attribution and checked findings. `test_demo_evidence.py` exercises them through canonical intake and the installed forensic tools. Memory remains an optional pinned download.

Small generated inputs elsewhere exercise bounded reads, malformed input, cancellation and other failure contracts. They are isolated unit fixtures, not demonstration evidence or a substitute for native parser validation.

`carving_samples.py` generates deterministic mixed raw images with known bytes and offsets from the JPEG plus small PNG, GIF, PDF, ZIP, BMP and PE fixtures. `test_live_carving.py` verifies native recovery bytes, duplicate occurrences, audits, profiles, limits and derived examinations. The optional public Word fixture is downloaded separately and pinned by SHA-256; see [carving validation](../../docs/carving-validation.md).
