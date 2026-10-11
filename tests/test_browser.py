"""Optional Chromium checks of the actual shared frontend execution flow."""
import sys
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest
from werkzeug.serving import make_server

from app import create_app
from sifted_core.storage import Repository
from sifted_core.worker import Worker
from sifted_core.workflow_catalog import WORKFLOWS

playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.browser
def test_preview_queue_completion_and_polling_without_event_stream(tmp_path):
    source = tmp_path / "evidence with spaces.bin"
    source.write_bytes(b"known forensic text\0")
    script = tmp_path / "strings.py"
    script.write_text("import time; time.sleep(0.2); print('0 known forensic text')")
    app = create_app({"TESTING": True, "SIFTED_DATABASE_PATH": str(tmp_path / "runtime.db"),
                      "SIFTED_INPUT_ROOTS": [str(tmp_path)], "SIFTED_OUTPUT_ROOTS": [str(tmp_path)],
                      "SIFTED_BINARIES": {"strings": [sys.executable, str(script)]}})
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    worker = Worker(Repository(app.config["DATABASE_PATH"]), app.config["SETTINGS"])
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip("Run python -m playwright install chromium to enable browser checks.")
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            for route in ("/strings", "/exiftool", "/foremost", "/scalpel", "/bulk-extractor", "/filetype", "/artifact-timeline", "/volatility", "/eric-zimmerman", "/cases", "/disk-analysis", "/file-examination", *("/workflow/" + tool for tool in WORKFLOWS)):
                page.goto(base + route)
                page.wait_for_timeout(200)
            assert not errors
            page.goto(base + "/strings")
            page.click('[data-source-mode="manual"]')
            page.fill('#sourcePath', str(source))
            page.fill('#outputPath', str(tmp_path / "results"))
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('evidence with spaces.bin')")
            assert '-n 4' in page.locator('#commandPreview').inner_text()
            # Losing the entire event stream must not lose terminal job status.
            page.route('**/api/run/*/events', lambda route: route.abort())
            page.click('#runStrings')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_function("document.querySelector('#runStatus').dataset.tone === 'success'", timeout=10000)
            assert page.locator('#runStrings').is_enabled()
            assert page.locator('#resultCount').inner_text() == '1'
            page.wait_for_selector('#runResultsLinks a')
            assert (tmp_path / "results/strings.txt").read_text().strip() == "0 known forensic text"
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
def test_filesystem_listing_extraction_and_derived_examination(tmp_path):
    source = tmp_path / "original disk.img"
    source.write_bytes(b"synthetic disk")
    script = tmp_path / "disk tools.py"
    script.write_text("import sys\ntool=sys.argv[1]\nif tool=='fls': print('r/r 42-128-1:\\tknown.bin')\nelif tool=='icat': sys.stdout.buffer.write(b'known derived bytes')\nelse: print('00000000: 6b 6e 6f 77 6e  known')\n")
    app = create_app({"TESTING": True, "SIFTED_DATABASE_PATH": str(tmp_path / "runtime.db"),
                      "SIFTED_INPUT_ROOTS": [str(tmp_path)], "SIFTED_OUTPUT_ROOTS": [str(tmp_path)],
                      "SIFTED_BINARIES": {tool: [sys.executable, str(script), tool] for tool in ("fls", "icat", "xxd")}})
    repo = Repository(app.config["DATABASE_PATH"])
    repo.add_case({"id": "case", "name": "Browser case", "slug": "case", "artifacts": []})
    worker = Worker(repo, app.config["SETTINGS"])
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip("Chromium is not installed.")
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/workflow/fls?" + urlencode({"case_id": "case", "source_path": str(source), "offset_sector": 2048}))
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('-o 2048')")
            page.click('#runWorkflow')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('#runResultsLinks a[href$="/analysis"]')
            page.click('#runResultsLinks a[href$="/analysis"]')
            page.click('a:has-text("Extract file")')
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('42-128-1')")
            assert page.locator('[data-parameter="offset_sector"]').input_value() == "2048"
            page.click('#runWorkflow')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('#runResultsLinks a[href$="/analysis"]')
            page.click('#runResultsLinks a[href$="/analysis"]')
            page.click('a[href*="/workflow/xxd?"]')
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('known.bin')")
            page.click('#runWorkflow')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_function("document.querySelector('#runStatus').dataset.tone === 'success'")
            runs = repo.runs(case_id="case")
            assert len(runs) == 3 and all(run["status"] == "success" for run in runs)
            examined = next(run for run in runs if run["tool"] == "xxd")
            extracted = next(run for run in runs if run["tool"] == "icat")
            assert repo.input(examined["id"])["source_run_id"] == extracted["id"]
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
