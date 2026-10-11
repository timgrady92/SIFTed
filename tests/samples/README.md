# Test samples

The repository contains two small JPEG fixtures in `images/`: `test_sample.jpg` and `geotagged.jpg`. The latter carries synthetic camera and GPS metadata. `test_live_tools.py` copies the fixture into isolated evidence directories and verifies metadata extraction, carving, and file identification through the application's adapters and worker.

Other inputs, including strings, feature extraction, timeline samples, and a minimal Unicode Windows shortcut, are generated in temporary test directories. No Windows registry, EVTX, Prefetch, or memory fixtures are bundled. Deterministic adapter tests verify argument construction and worker behavior; they do not establish those parsers' forensic accuracy on real evidence.
