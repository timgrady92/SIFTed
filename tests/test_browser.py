"""Optional Chromium checks of the actual shared frontend execution flow."""
import sys
import threading
from pathlib import Path
from urllib.parse import urlencode, parse_qs, urlparse

import pytest
from werkzeug.serving import make_server

from app import create_app
from sifted_core.storage import Repository
from sifted_core.worker import Worker
from sifted_core.workflow_catalog import WORKFLOWS
from test_volatility import memory_runtime as memory_runtime
from test_carving import carving_runtime as carving_runtime
from test_zimmerman import zimmerman_runtime as zimmerman_runtime

playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.browser
def test_volatility_tabs_options_and_64_bit_addresses(memory_runtime, monkeypatch):
    from sifted_core import web
    repo, settings, source, installed = memory_runtime
    monkeypatch.setattr(web, "discover_volatility", lambda settings: installed)
    app = create_app({"TESTING": True, "SIFTED_DATABASE_PATH": str(source.parent / "runtime.db"),
                      "SIFTED_INPUT_ROOTS": settings.input_roots, "SIFTED_OUTPUT_ROOTS": settings.output_roots,
                      "SIFTED_VOLATILITY_SYMBOLS": settings.volatility_symbols})
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
            page.goto(f"http://127.0.0.1:{server.server_port}/volatility")
            page.click('[data-source-mode="manual"]')
            page.fill('#sourcePath', str(source))
            page.fill('#outputPath', str(source.parent / "results"))
            page.check('[data-plugin="windows.pslist.PsList"]')
            page.locator('[data-plugin-options="windows.pslist.PsList"] summary').click()
            page.fill('[data-plugin-options="windows.pslist.PsList"] [data-option="offset"]', '0xffff800000123001')
            page.fill('[data-plugin-options="windows.pslist.PsList"] [data-option="pid"]', '[4]')
            page.click('[data-tab="linux"]')
            page.check('[data-plugin="linux.pagecache.RecoverFs"]')
            assert page.evaluate('buildPayload().plugins') == ['linux.pagecache.RecoverFs']
            page.click('[data-tab="windows"]')
            page.select_option('#renderer', 'jsonl')
            expected = int('0xffff800000123001', 16)
            page.wait_for_function('(value) => document.querySelector("#commandPreview").textContent.includes(value)',
                                   arg='--offset=' + str(expected))
            page.route('**/api/run/*/events', lambda route: route.abort())
            page.click('#runVolatility')
            page.wait_for_function('document.querySelector("#runStatus").textContent.includes("Queued")')
            Worker(repo, settings).run_once()
            page.wait_for_function('document.querySelector("#runStatus").dataset.tone === "success"', timeout=10000)
            run = repo.runs()[0]
            assert run['plan']['parameters']['plugin_options']['windows.pslist.PsList']['offset'] == expected
            assert run['plan']['parameters']['plugins'] == ['windows.pslist.PsList']
            page.wait_for_selector('#runResultsLinks a')
            assert 'success (2 rows)' in page.locator('#runResultsLinks').inner_text()
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
            page.wait_for_function("document.querySelector('#copyTerminal').disabled")
            page.click('[data-source-mode="manual"]')
            page.fill('#sourcePath', str(source))
            page.fill('#outputPath', str(tmp_path / "results"))
            page.wait_for_function("!document.querySelector('#copyTerminal').disabled")
            assert '-n 4' in ' '.join(page.locator('#commandPreview').inner_text().replace('\\\n', ' ').split())
            assert page.locator('#commandPreview').inner_text().startswith("bash <<'")
            assert '<staging_output>' not in page.locator('#commandPreview').inner_text()
            # Copy includes every line, even when the displayed block scrolls.
            page.evaluate("() => { window.copiedSnippet = ''; document.execCommand = () => { window.copiedSnippet = document.querySelector('textarea').value; return true; }; }")
            page.evaluate("Object.defineProperty(window, 'isSecureContext', {value: false});")
            page.click('#copyTerminal')
            assert page.evaluate('window.copiedSnippet') == page.locator('#commandPreview').inner_text()
            with page.expect_download() as downloaded:
                page.click('#downloadTerminal')
            saved = tmp_path / "saved snippet.sh"
            downloaded.value.save_as(str(saved))
            assert saved.read_text() == page.evaluate('window.copiedSnippet')
            page.fill('#sourcePath', str(tmp_path / 'missing evidence'))
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('Source must be')")
            assert page.locator('#copyTerminal').is_disabled()
            page.fill('#sourcePath', str(source))
            page.wait_for_function("!document.querySelector('#copyTerminal').disabled")
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


@pytest.mark.browser
@pytest.mark.parametrize('tool',['foremost','scalpel'])
def test_carving_recovery_table_and_hash_verified_followup(carving_runtime, tool):
    repo,settings,source,_=carving_runtime
    repo.add_case({'id':'case','name':'Carving browser case','slug':'case','artifacts':[]})
    app=create_app({'TESTING':True,'SIFTED_DATABASE_PATH':str(repo.path),'SIFTED_INPUT_ROOTS':settings.input_roots,
                    'SIFTED_OUTPUT_ROOTS':settings.output_roots,'SIFTED_BINARIES':settings.binaries})
    server=make_server('127.0.0.1',0,app,threaded=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    errors=[]
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():pytest.skip('Chromium is not installed')
            browser=engine.chromium.launch(headless=True);page=browser.new_page()
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}/'+tool)
            page.click('[data-source-mode="manual"]');page.select_option('#caseSelect','case')
            page.fill('#sourcePath',str(source));page.fill('#outputPath',str(source.parent/'results'))
            page.uncheck('.chip input[value="pdf"]')
            page.wait_for_function('document.querySelector("#commandPreview").textContent.includes("carver.py")')
            page.route('**/api/run/*/events',lambda route:route.abort())
            page.click('#run'+tool.title())
            page.wait_for_function('document.querySelector("#runStatus").textContent.includes("Queued")')
            Worker(repo,app.config['SETTINGS']).run_once()
            page.wait_for_function('document.querySelector("#runStatus").dataset.tone === "success"',timeout=10000)
            page.wait_for_selector('#runResultsLinks a[href$="/analysis"]')
            page.click('#runResultsLinks a[href$="/analysis"]')
            assert '1 recovered files' in page.locator('main').inner_text()
            assert 'Offset Bytes' in page.locator('table').inner_text()
            page.click('a[href*="/workflow/xxd?"]')
            page.wait_for_function('document.querySelector("#commandPreview").textContent.includes("00000000.jpg")')
            page.click('#runWorkflow')
            page.wait_for_function('document.querySelector("#runStatus").textContent.includes("Queued")')
            Worker(repo,app.config['SETTINGS']).run_once()
            page.wait_for_function('document.querySelector("#runStatus").dataset.tone === "success"',timeout=10000)
            runs=repo.runs(case_id='case');assert len(runs)==2 and all(run['status']=='success' for run in runs)
            examined=next(run for run in runs if run['tool']=='xxd')
            producer=next(run for run in runs if run['tool']==tool)
            assert repo.input(examined['id'])['source_run_id']==producer['id']
            assert producer['plan']['parameters']['types']==['jpg']
            assert not errors
            browser.close()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)


@pytest.mark.browser
def test_zimmerman_parser_options_queue_and_mapped_sqlite_results(zimmerman_runtime):
    from test_zimmerman import input_for
    repo, settings, evidence, outputs, _ = zimmerman_runtime
    source = input_for(zimmerman_runtime, 'sqlecmd')
    app = create_app({'TESTING':True, 'SIFTED_DATABASE_PATH':str(evidence.parent/'runtime.db'),
                      'SIFTED_INPUT_ROOTS':settings.input_roots,'SIFTED_OUTPUT_ROOTS':settings.output_roots,
                      'SIFTED_EZ_ROOT':settings.ez_root, 'SIFTED_BINARIES':settings.binaries})
    server=make_server('127.0.0.1',0,app,threaded=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    errors=[]
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():pytest.skip('Chromium is not installed.')
            browser=engine.chromium.launch(headless=True);page=browser.new_page()
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}/eric-zimmerman')
            page.click('[data-tool-id="recmd"]')
            assert page.locator('[data-parser-option="batch"]').input_value()=='RegistryASEPs'
            page.check('[data-parser-option="ignore_transaction_logs"]')
            page.click('[data-tool-id="jlecmd"]')
            assert page.locator('[data-parser-option="batch"]').count()==0
            assert page.locator('[data-parser-option="ignore_transaction_logs"]').count()==0
            page.check('[data-parser-option="include_unlisted"]')
            page.click('[data-tool-id="sqlecmd"]')
            assert 'SIFTed executor' in page.locator('#ezToolStatus').inner_text()
            assert page.locator('[data-parser-option="include_unlisted"]').count()==0
            page.select_option('[data-parser-option="maps"]',['test.smap'])
            page.click('[data-source-mode="manual"]');page.fill('#sourcePath',str(source))
            page.fill('#outputPath',str(outputs/'browser parsed'))
            page.wait_for_function('document.querySelector("#commandPreview").textContent.includes("sqlite-request.json")')
            page.route('**/api/run/*/events',lambda route:route.abort())
            page.click('#runEzTool')
            try:
                page.wait_for_function('document.querySelector("#runStatus").textContent.includes("Queued")', timeout=10000)
            except playwright.TimeoutError:
                pytest.fail(f"Queue submission failed: {page.locator('#runStatus').inner_text()}; browser errors: {errors}")
            Worker(repo,settings).run_once()
            page.wait_for_function('document.querySelector("#runStatus").dataset.tone === "success"',timeout=10000)
            result=repo.runs()[0]
            assert result['analysis']['entry_count']==1 and result['plan']['parameters']['maps']==['test.smap']
            assert 'include_unlisted' not in result['plan']['parameters']
            page.wait_for_selector('#runResultsLinks a')
            page.click('#runResultsLinks a:has-text("Inspect structured results")')
            assert 'known value' in page.locator('body').inner_text()
            assert not errors
            browser.close()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)


from test_integrated_tools import integrated as integrated
from test_evidence_workspace import workspace_runtime as workspace_runtime


@pytest.mark.browser
def test_evidence_workspace_disk_journey_and_mobile_layout(workspace_runtime, tmp_path):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    worker = Worker(repo, settings)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': 390, 'height': 844})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            workspace_url = base + f'/case/{case}/workspace?' + urlencode({'input': key})
            page.goto(workspace_url)
            assert page.locator('[data-evidence-action="mmls"]').count() == 1
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(tmp_path/'workspace-mobile.png'), full_page=True)
            page.locator('[data-evidence-action="mmls"] a').click()
            page.wait_for_function("!document.querySelector('#copyTerminal').disabled")
            assert page.locator('#caseSelect').input_value() == case
            assert page.locator('#sourcePath').input_value() == str(source)
            with page.expect_request('**/api/mmls/run') as submitted:
                page.click('#runWorkflow')
            assert submitted.value.post_data_json['workspace_input'] == key
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('#runResultsLinks a[href*="/analysis"]')
            page.click('#runResultsLinks a[href*="/analysis"]')
            page.get_by_role('link', name='← Return to evidence workspace').click()
            page.locator('.evidence-filesystem a', has_text='Browse files').click()
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('-o 2048')")
            page.click('#runWorkflow')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('#runResultsLinks a[href*="/analysis"]')
            page.click('#runResultsLinks a[href*="/analysis"]')
            page.get_by_role('link', name='Extract file').first.click()
            page.wait_for_function("document.querySelector('#commandPreview').textContent.includes('42-128-1')")
            page.click('#runWorkflow')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('#runResultsLinks a[href*="/analysis"]')
            page.click('#runResultsLinks a[href*="/analysis"]')
            page.locator('a[href*="/workflow/xxd?"]').click()
            page.wait_for_function("!document.querySelector('#copyTerminal').disabled")
            assert parse_qs(urlparse(page.url).query)['workspace_input'][0].startswith('d:')
            assert page.locator('#sourcePath').input_value() != str(source)
            page.click('#runWorkflow')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('#runResultsLinks a[href*="/analysis"]')
            page.click('#runResultsLinks a[href*="/analysis"]')
            page.get_by_role('link', name='← Return to evidence workspace').click()
            assert page.locator('[data-evidence-action="xxd"] a', has_text='View latest successful result').count() == 1
            assert len(repo.runs()) == 4 and all(r['status'] == 'success' for r in repo.runs())
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
def test_evidence_workspace_prefills_specific_zimmerman_parser(zimmerman_runtime):
    from test_zimmerman import input_for
    from test_evidence_workspace import register
    repo, settings, evidence, outputs, native = zimmerman_runtime
    source = input_for(zimmerman_runtime, 'sqlecmd')
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(repo.path), 'SIFTED_INPUT_ROOTS': settings.input_roots,
                      'SIFTED_OUTPUT_ROOTS': settings.output_roots, 'SIFTED_EZ_ROOT': settings.ez_root, 'SIFTED_BINARIES': settings.binaries})
    case, key = register(app.test_client(), repo, source)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + f'/case/{case}/workspace?' + urlencode({'input': key}))
            page.locator('[data-evidence-action="sqlecmd"] a').click()
            page.wait_for_function("!document.querySelector('#copyTerminal').disabled")
            assert page.locator('.ez-tool-card.active').get_attribute('data-tool-id') == 'sqlecmd'
            assert page.locator('#sourcePath').input_value() == str(source)
            assert page.locator('#caseSelect').input_value() == case
            page.click('#runEzTool')
            page.wait_for_function("document.querySelector('#runStatus').textContent.includes('Queued')")
            Worker(repo, app.config['SETTINGS']).run_once()
            page.wait_for_function("document.querySelector('#runStatus').dataset.tone === 'success'")
            page.get_by_role('link', name='← Return to evidence workspace').click()
            assert page.locator('[data-evidence-action="sqlecmd"] a', has_text='View latest successful result').count() == 1
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
