"""Optional Chromium checks of the actual shared frontend execution flow."""
import sys
import shlex
import threading
from pathlib import Path
from urllib.parse import urlencode, parse_qs, urlparse

import pytest
from werkzeug.serving import make_server

from app import create_app
from sifted_core.storage import Repository
from sifted_core.worker import Worker
from sifted_core.workflow_catalog import WORKFLOWS
from sifted_core.yara_rules import DEFAULT_RULES
from test_volatility import memory_runtime as memory_runtime
from test_carving import carving_runtime as carving_runtime
from test_zimmerman import zimmerman_runtime as zimmerman_runtime
from test_evidence_intake import intake_runtime as intake_runtime
from test_evidence_assessment import assessed_intake as assessed_intake

playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_automatic_memory_workflow_uses_progressive_disclosure(assessed_intake, width):
    runtime, _ = assessed_intake
    client, repo, settings, case, root = runtime
    source = root / 'misleading.jpg'
    source.write_bytes(b'\0' * 1024 ** 2)
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(source)})
    key = 'e:' + response.json['artifact']['id']
    server = make_server('127.0.0.1', 0, client.application, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': width, 'height': 900})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + f'/case/{case}/workspace?' + urlencode({'input': key}))
            Worker(repo, settings).run_once()
            page.get_by_role('heading', name='Prepare memory analysis', exact=True).wait_for()
            assert page.get_by_role('tab', name='Processes', exact=True).count() == 1
            assert page.locator('#evidenceTypeForm').count() == 0
            assert page.locator('#memoryContextForm').is_hidden()
            page.locator('[data-disclosure="memory-context"] summary').click()
            assert page.locator('#memoryContextForm').is_visible()
            page.get_by_role('link', name='All evidence', exact=True).click()
            card = page.locator(f'[data-evidence-key="{key}"]')
            assert 'Memory image' in card.inner_text() and 'Set type' not in card.inner_text()
            card.click()
            page.get_by_role('heading', name='Prepare memory analysis', exact=True).wait_for()
            assert page.locator('#memoryContextForm').is_hidden()
            page.get_by_role('tab', name='Overview', exact=True).click()
            assert page.get_by_text('application/etl', exact=True).is_hidden()
            page.locator('[data-disclosure="identification"] summary').click()
            assert page.get_by_text('application/etl', exact=True).is_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
            command = page.locator('#commandPreview').inner_text()
            assert command.count('\n') == 1
            assert shlex.quote(str(source)) in command
            assert '>' not in command and 'mkdir' not in command
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
            page.wait_for_url('**/workflow/xxd?**')
            page.locator('#commandPreview').wait_for()
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
            page.wait_for_function('document.querySelector("#commandPreview").textContent.includes("sqlite3 -readonly")')
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
@pytest.mark.parametrize("width", [390, 1440])
def test_evidence_workspace_disk_journey_and_mobile_layout(workspace_runtime, tmp_path, width):
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
            page = browser.new_page(viewport={'width': width, 'height': 844})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            workspace_url = base + f'/case/{case}/workspace?' + urlencode({'input': key})
            page.goto(workspace_url)
            assert page.get_by_role('button', name='Map disk', exact=True).count() == 1
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(tmp_path/'workspace-mobile.png'), full_page=True)
            page.get_by_text('Disk options', exact=True).click()
            page.get_by_role('button', name='Configure disk map', exact=True).click()
            page.select_option('[data-field="sector_size"]', '4096')
            page.wait_for_function("!document.querySelector('#copyOperation').disabled && document.querySelector('#operationCommand').textContent.includes('-b 4096')")
            assert all(run['tool'] == 'evidence-intake' for run in repo.runs())
            page.click('#closeOperation')
            with page.expect_request('**/api/mmls/run') as submitted:
                page.get_by_role('button', name='Map disk', exact=True).click()
            assert submitted.value.post_data_json['workspace_input'] == key
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            page.reload()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('progress')")
            page.evaluate("window.workspaceDocument = 'kept through the journey'")
            page.route('**/api/run/*/status', lambda route: route.abort(), times=1)
            worker.run_once()
            page.get_by_role('button', name='Analyze filesystem', exact=True).wait_for()
            assert page.get_by_role('button', name='Analyze filesystem', exact=True).evaluate('(element) => element === document.activeElement')
            page.get_by_role('button', name='Analyze filesystem', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.get_by_role('button', name='Build file inventory', exact=True).first.wait_for()
            page.get_by_role('button', name='Build file inventory', exact=True).first.click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.get_by_role('link', name='Explore files', exact=True).click()
            page.wait_for_selector('#triageFilters')
            assert not page.locator('.triage-filter-options').get_attribute('open')
            page.fill('input[name="q"]', 'spaces')
            page.locator('.triage-filter-options summary').click()
            page.select_option('select[name="state"]', 'deleted')
            page.wait_for_function("document.querySelectorAll('[data-triage-entry]').length === 1")
            assert page.locator('[data-triage-entry]').count() == 1
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(tmp_path/'triage-mobile.png'), full_page=True)
            assert page.get_by_role('button', name='Recover file', exact=True).is_hidden()
            page.get_by_role('button', name='Inspect deleted file with spaces.txt', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_function("document.querySelector('#operationResult').textContent.includes('Filesystem metadata')")
            assert page.locator('#workspaceOperation').locator('xpath=ancestor::tr').get_attribute('id').startswith('entry-')
            before_metadata_reopen = len(repo.runs())
            page.get_by_role('button', name='Close inspection', exact=True).click()
            page.get_by_role('button', name='Inspect deleted file with spaces.txt', exact=True).click()
            page.wait_for_function("document.querySelector('#operationResult').textContent.includes('Filesystem metadata')")
            assert len(repo.runs()) == before_metadata_reopen
            page.get_by_role('button', name='Recover file', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            assert '42-128-1' in page.locator('#operationCommand').text_content()
            worker.run_once()
            page.get_by_role('button', name='Examine captured file', exact=True).wait_for()
            assert page.locator('[data-active-tab=triage]').count() == 1
            page.get_by_role('button', name='Examine captured file', exact=True).click()
            page.get_by_role('tab', name='File triage', exact=True).click()
            page.wait_for_selector('#triageFilters')
            assert page.locator('input[name="q"]').input_value() == 'spaces'
            assert page.locator('select[name="state"]').input_value() == 'deleted'
            assert page.locator('[data-triage-entry]').count() == 1
            page.locator('[data-workspace-tab="derived"]').click()
            page.wait_for_selector('#derivedExamination')
            assert page.locator('#workspaceTabPanel [data-evidence-key]').count() == 0
            page.locator('[data-evidence-action="xxd"] [data-workspace-tool]').click()
            page.wait_for_function("!document.querySelector('#copyOperation').disabled")
            assert parse_qs(urlparse(page.url).query)['input'][0] == key
            assert parse_qs(urlparse(page.url).query)['examine'][0].startswith('d:')
            assert 'deleted file with spaces.txt' in page.locator('#operationCommand').text_content()
            assert not page.locator('#operationOptions').get_attribute('open')
            assert not page.locator('#operationCli').get_attribute('open')
            page.click('#runOperation')
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.wait_for_selector('[data-evidence-action="xxd"] [data-workspace-result]', state='attached')
            assert len(repo.runs()) == 7 and all(r['status'] == 'success' for r in repo.runs())
            assert urlparse(page.url).path == urlparse(workspace_url).path
            assert page.evaluate('window.workspaceDocument') == 'kept through the journey'
            page.reload()
            page.wait_for_function("document.querySelector('#operationResult').textContent.includes('00000000')")
            page.click('#closeOperation')
            page.wait_for_selector('[data-evidence-action="xxd"] [data-workspace-result]')
            page.locator('[data-evidence-action="xxd"] [data-workspace-result]').click()
            page.wait_for_function("document.querySelector('#operationResult').textContent.includes('00000000')")
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.set_viewport_size({'width': 1440, 'height': 1000})
            page.evaluate('window.scrollTo(0, 0)')
            page.screenshot(path=str(tmp_path/'workspace-desktop.png'), full_page=True)
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
            page.locator('[data-evidence-action="sqlecmd"] [data-workspace-tool]').click()
            page.wait_for_function("!document.querySelector('#copyOperation').disabled")
            assert str(source) in page.locator('#operationCommand').text_content()
            page.click('#runOperation')
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            Worker(repo, app.config['SETTINGS']).run_once()
            page.wait_for_selector('[data-evidence-action="sqlecmd"] [data-workspace-result]', state='attached')
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
def test_workspace_jobs_follow_their_evidence_and_can_be_cancelled(workspace_runtime):
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    second = source.parent / 'second disk.img'
    second.write_bytes(source.read_bytes())
    registered = client.post(f'/api/case/{case}/artifacts', json={'path': str(second), 'type': 'disk_image'}).json['artifact']
    Worker(repo, settings).run_once()
    second_key = 'e:' + registered['id']
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
            page.goto(f'http://127.0.0.1:{server.server_port}/case/{case}/workspace?' + urlencode({'input': key}))
            page.get_by_role('button', name='Map disk', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            page.get_by_role('link', name='All evidence', exact=True).click()
            page.locator(f'[data-evidence-key="{second_key}"]').click()
            page.get_by_role('heading', name=second.name, exact=True).wait_for()
            Worker(repo, settings).run_once()
            page.reload()
            page.get_by_role('button', name='Map disk', exact=True).wait_for()
            assert page.locator('[data-filesystem-offset]').count() == 0
            page.get_by_role('button', name='Map disk', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            page.click('#cancelOperation')
            page.wait_for_function("document.querySelector('#operationStatus').dataset.tone === 'error'")
            assert sorted(run['status'] for run in repo.runs() if run['tool'] != 'evidence-intake') == ['cancelled', 'success']
            assert page.locator('[data-filesystem-offset]').count() == 0
            page.get_by_role('link', name='All evidence', exact=True).click()
            page.locator(f'[data-evidence-key="{key}"]').click()
            page.wait_for_selector('[data-filesystem-offset]')
            assert parse_qs(urlparse(page.url).query)['input'] == [key]
            assert len(repo.runs()) == 4 and not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_workspace_inspection_keeps_position_drafts_and_keyboard_context(workspace_runtime, width, tmp_path):
    from test_file_triage import inventory
    inventory(workspace_runtime, records=[f'r/r {100+i}: item{i:03}.txt' for i in range(95)])
    app, client, repo, settings, source, outputs, case, key = workspace_runtime
    worker = Worker(repo, settings)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': width, 'height': 900})
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}/case/{case}/workspace?' + urlencode({'input': key, 'tab': 'triage'}))
            selected = page.get_by_role('button', name='Inspect item070.txt', exact=True)
            selected.scroll_into_view_if_needed()
            before = page.evaluate('scrollY')
            selected.click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            assert page.evaluate('scrollY') >= before - 2  # Never jump above the selected entry.
            queued = page.evaluate('scrollY')
            worker.run_once()
            page.wait_for_selector('.triage-detail-row:not([hidden]) [data-workspace-result]', state='attached')
            assert abs(page.evaluate('scrollY') - queued) < 3
            assert page.locator('#workspaceOperation').locator('xpath=ancestor::tr').get_attribute('id') == page.locator('.triage-detail-row:not([hidden])').get_attribute('id')
            page.screenshot(path=str(tmp_path / f'inline-inspection-{width}.png'))
            # A completed background job must not erase a draft query or steal focus.
            page.get_by_role('button', name='Inspect item071.txt', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            query = page.locator('#triageFilters input[name=q]')
            query.fill('unfinished search')
            query.focus()
            worker.run_once()
            page.wait_for_selector('.triage-detail-row:not([hidden]) [data-workspace-result]', state='attached')
            assert query.input_value() == 'unfinished search'
            assert query.evaluate('(element) => document.activeElement === element')
            # Manual keyboard navigation retains a usable tab stop and exposes the active tab on mobile.
            page.locator('#tab-triage').focus()
            page.keyboard.press('ArrowRight')
            page.wait_for_selector('[data-active-tab=derived]')
            assert page.locator('#tab-derived').evaluate('(element) => element === document.activeElement && element.getAttribute("aria-selected") === "true"')
            bounds = page.locator('#tab-derived').bounding_box()
            assert bounds['x'] >= 0 and bounds['x'] + bounds['width'] <= width
            page.keyboard.press('ArrowLeft')
            page.wait_for_selector('[data-active-tab=triage]')
            assert page.locator('.triage-detail-row:not([hidden])').count() == 1
            # Returning to an existing entry reads its report without another job.
            count = len(repo.runs())
            page.get_by_role('button', name='Inspect item071.txt', exact=True).click()
            page.wait_for_function("document.querySelector('#operationResult').textContent.includes('known bytes')")
            assert len(repo.runs()) == count
            page.locator('#tab-activity').click()
            page.wait_for_selector('[data-active-tab=activity]')
            page.go_back()
            page.wait_for_selector('[data-active-tab=triage]')
            assert page.locator('.triage-detail-row:not([hidden])').count() == 1
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)




@pytest.mark.browser
@pytest.mark.parametrize(('method', 'width'), [('upload', 390), ('path', 1280)])
def test_evidence_intake_from_browser_to_verified_overview(intake_runtime, method, width, tmp_path):
    import hashlib
    import json
    client, repo, settings, case, inputs = intake_runtime
    app = client.application
    sample = inputs / 'a document.raw'
    sample.write_bytes(b'%PDF-1.7\nKnown uploaded evidence\n')
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': width, 'height': 900})
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}/cases')
            page.locator('.case-toggle').click()
            page.locator('.add-artifact-btn').click()
            page.select_option('#intakeMethod', method)
            if method == 'upload':
                page.set_input_files('#evidenceFiles', str(sample))
            else:
                page.fill('#artifactPath', str(sample))
            page.fill('#intakeCustodian', 'Browser examiner')
            page.locator('#addArtifactForm summary').click()
            page.fill('#intakeHash', expected)
            page.locator('#addArtifactForm').get_by_role('button', name='Add evidence', exact=True).click()
            page.wait_for_url('**/workspace?**', timeout=10000)
            assert 'Verifying' in page.locator('#workspaceTabPanel').inner_text()
            assert repo.runs()[0]['status'] == 'queued'
            Worker(repo, settings).run_once()
            page.get_by_role('button', name='Continue to Analysis').wait_for(timeout=15000)
            text = page.locator('#workspaceTabPanel').inner_text()
            assert expected in text and 'PDF document' in text and 'Verified' in text
            page.get_by_text('Custody and file manifest', exact=True).click()
            with page.expect_download() as download:
                page.get_by_role('link', name='Download custody record and hashes').click()
            audit = json.loads(Path(download.value.path()).read_text())
            assert audit['evidence']['hash'] == expected and audit['custody']['event_count'] == 4
            page.get_by_role('button', name='Verify integrity', exact=True).click()
            page.wait_for_function("document.querySelector('#workspaceTabPanel').textContent.includes('Verifying')")
            Worker(repo, settings).run_once()
            page.get_by_role('button', name='Verify integrity', exact=True).wait_for(timeout=15000)
            assert len(repo.runs()) == 2 and all(run['status'] == 'success' for run in repo.runs())
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(tmp_path / f'intake-{method}.png'), full_page=True)
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


from test_memory_workspace import memory_workspace as memory_workspace, family_inventory


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_bundled_yara_defaults_in_guided_and_standalone_ui(memory_workspace, monkeypatch, width):
    from sifted_core import web
    from test_volatility import option
    app, _, repo, settings, _, case, key, installed = memory_workspace
    plugin = 'windows.vadyarascan.VadYaraScan'
    installed['plugins'][plugin]['options'] += [option('yara_string', 'string'), option('yara_compiled_file', 'file')]
    monkeypatch.setattr(web, 'discover_volatility', lambda _settings: installed)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': width, 'height': 844})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + f'/case/{case}/workspace?' + urlencode({
                'input': key, 'tab': 'investigate', 'memory_question': 'indicators'}))
            page.get_by_role('button', name='Scan mapped memory with YARA rules', exact=True).click()
            field = page.get_by_label('YARA rules file', exact=True)
            assert field.input_value() == str(DEFAULT_RULES)
            page.wait_for_function("!document.querySelector('#runOperation').disabled")
            assert '--yara-file ' + str(DEFAULT_RULES) in page.locator('#operationCommand').text_content()
            page.get_by_role('button', name='Run volatility', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            run_id = parse_qs(urlparse(page.url).query)['run'][0]
            Worker(repo, settings).run_once()
            page.get_by_text('YARA rules · 72 indicators', exact=True).wait_for()
            assert not page.locator(f'[data-disclosure="yara-library-{run_id}"]').evaluate('(el) => el.open')
            page.get_by_text('YARA rules · 72 indicators', exact=True).click()
            assert page.get_by_role('link', name='Rules used', exact=True).is_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert repo.run(run_id)['plan']['parameters']['plugin_options'][plugin]['yara_file'] == str(DEFAULT_RULES)
            page.goto(base + '/volatility')
            page.locator(f'[data-plugin="{plugin}"]').check()
            block = page.locator(f'[data-plugin-options="{plugin}"]')
            assert block.locator('[data-option="yara_file"]').input_value() == str(DEFAULT_RULES)
            block.locator('summary').click()
            block.locator('[data-option="yara_string"]').fill('known marker')
            values = page.evaluate('buildPayload()')['plugin_options'][plugin]
            assert values['yara_string'] == 'known marker' and 'yara_file' not in values
            block.locator('[data-option="yara_string"]').fill('')
            assert page.evaluate('buildPayload()')['plugin_options'][plugin]['yara_file'] == str(DEFAULT_RULES)
            assert page.get_by_role('link', name='Symbol setup guide', exact=True).get_attribute('href') == '/guides/volatility-symbols'
            page.goto(base + '/guides/volatility-symbols')
            assert page.get_by_role('heading', name='Volatility symbols', exact=True).is_visible()
            assert page.get_by_text('Offline symbol packs', exact=True).is_visible()
            assert not page.locator('details').first.evaluate('(el) => el.open')
            page.get_by_text('Offline symbol packs', exact=True).click()
            assert page.get_by_role('link', name='linux.zip', exact=True).is_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert page.evaluate("Array.from(document.querySelectorAll('.symbol-guide .command')).filter(el => el.getClientRects().length).every(el => el.getBoundingClientRect().right <= el.closest('.card').getBoundingClientRect().right)")
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_process_family_navigation_and_history(memory_workspace, width, tmp_path):
    app, _, repo, _, _, case, key, _ = memory_workspace
    run = family_inventory(memory_workspace)
    run_count = len(repo.runs())
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': width, 'height': 844})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + f'/case/{case}/workspace?' + urlencode({
                'input': key, 'tab': 'processes', 'inventory_run_id': run['id'],
                'process_q': 'process-42.exe', 'process_row': 43}))
            page.evaluate("window.familyDocument = 'same document'")
            page.locator('[data-disclosure="process-record-43"] summary').click()
            parent = page.locator('[data-process-entry="43"] [data-process-target="91"]')
            parent.scroll_into_view_if_needed()
            parent.focus()
            original_scroll = page.evaluate('scrollY')
            original_url = page.url
            parent.press('Enter')
            page.wait_for_function("document.activeElement.id === 'process-91'")
            assert page.locator('[data-process-entry]').first.get_attribute('data-process-entry') == '51'
            assert page.locator('[name=process_q]').input_value() == ''
            assert page.locator('#process-91').inner_text() == 'Process 900'
            assert page.locator('#process-91').bounding_box()['y'] >= page.locator('.workspace-tabs').bounding_box()['height']
            assert page.locator('#process-91').bounding_box()['y'] < 200
            children = page.locator('[data-disclosure="process-children-91"]')
            assert children.locator('summary').inner_text() == 'Children (2)'
            assert not children.evaluate('(el) => el.open')
            children.locator('summary').click()
            page.screenshot(path=str(tmp_path / f'process-family-{width}.png'))
            assert children.get_by_role('link', name='Inspect process 42 · process-42.exe', exact=True).is_visible()
            child = children.get_by_role('link', name='Inspect process 109 · process-109.exe', exact=True)
            child.focus()
            parent_scroll = page.evaluate('scrollY')
            child.press('Enter')
            page.wait_for_function("document.activeElement.id === 'process-110'")
            assert page.locator('[data-process-entry]').first.get_attribute('data-process-entry') == '101'
            assert page.locator('#process-110').bounding_box()['y'] < 200
            page.go_back()
            page.wait_for_function("document.querySelector('#process-91') && !document.querySelector('#workspaceView').hasAttribute('aria-busy')")
            assert children.evaluate('(el) => el.open')
            assert abs(page.evaluate('scrollY') - parent_scroll) < 3
            assert page.evaluate('document.activeElement.dataset.processTarget') == '110'
            page.go_back()
            page.wait_for_function("document.querySelector('#process-43') && !document.querySelector('#workspaceView').hasAttribute('aria-busy')")
            assert page.url == original_url
            assert page.locator('[name=process_q]').input_value() == 'process-42.exe'
            assert page.locator('[data-disclosure="process-record-43"]').evaluate('(el) => el.open')
            assert abs(page.evaluate('scrollY') - original_scroll) < 3
            assert page.evaluate('document.activeElement.dataset.processTarget') == '91'
            page.go_forward()
            page.wait_for_function("document.querySelector('#process-91') && !document.querySelector('#workspaceView').hasAttribute('aria-busy')")
            page.go_forward()
            page.wait_for_function("document.activeElement.id === 'process-110'")
            assert page.evaluate('window.familyDocument') == 'same document'
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.reload()
            assert page.locator('#process-110').is_visible()
            assert parse_qs(urlparse(page.url).query)['inventory_run_id'] == [run['id']]
            assert len(repo.runs()) == run_count
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_guided_memory_journey_resume_process_scope_and_mobile(memory_workspace, width, tmp_path):
    app, client, repo, settings, source, case, key, _ = memory_workspace
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
            page = browser.new_page(viewport={'width': width, 'height': 844})
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}/case/{case}/workspace?' + urlencode({'input': key}))
            page.get_by_role('button', name='Identify image', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            page.reload()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('progress')")
            page.evaluate("window.memoryDocument = 'same document'")
            worker.run_once()
            page.get_by_role('button', name='Build process inventory', exact=True).wait_for()
            assert page.locator('#workspaceOperation').is_hidden()
            page.get_by_role('button', name='Build process inventory', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.get_by_role('link', name='Review processes', exact=True).click()
            page.wait_for_selector('#memoryFilters')
            assert page.locator('[data-process-entry]').count() == 50
            page.get_by_role('button', name='Next', exact=True).click()
            page.wait_for_function("document.querySelector('[data-process-entry]').dataset.processEntry === '51'")
            page.fill('[name=process_q]', 'process-42.exe')
            page.get_by_role('button', name='Search', exact=True).click()
            page.wait_for_function("document.querySelectorAll('[data-process-entry]').length === 1")
            page.get_by_role('button', name='Inspect', exact=True).click()
            page.get_by_role('button', name='Read command line', exact=True).wait_for()
            assert page.locator('.memory-process-table > thead > tr > th').all_text_contents()[:2] == ['PID', 'PPID']
            page.get_by_text('Recorded process details', exact=True).click()
            assert '18446735277616529450' in page.locator('.triage-inspector').inner_text()
            page.get_by_role('button', name='Read command line', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            assert '--pid 42' in page.locator('#operationCommand').text_content()
            assert str(source) in page.locator('#operationCommand').text_content()
            first = parse_qs(urlparse(page.url).query)['run'][0]
            # A different plugin for the same image/PID must create its own job.
            page.get_by_role('button', name='Inspect loaded modules', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            second = parse_qs(urlparse(page.url).query)['run'][0]
            assert first != second
            worker.run_once()
            worker.run_once()
            page.wait_for_function("document.querySelector('#operationResult').textContent.includes('18446735277616529450')")
            assert page.locator('#workspaceOperation').locator('xpath=ancestor::section[@data-operation-slot]').get_attribute('data-operation-slot') == 'process-43'
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert page.locator('.workspace-result-table thead').evaluate('(el) => getComputedStyle(el).clipPath') == 'none'
            assert page.locator('.workspace-result-table tbody tr').first.evaluate('(el) => getComputedStyle(el).display') == 'table-row'
            page.evaluate('window.scrollTo(0, 0)')
            page.screenshot(path=str(tmp_path/f'memory-process-{width}.png'), full_page=True)
            page.get_by_role('button', name='Extract executable', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            capture = page.locator('#operationResult .evidence-card[data-examine]')
            capture.wait_for()
            captured_key = capture.get_attribute('data-examine')
            captured_url = capture.get_attribute('href')
            assert parse_qs(urlparse(captured_url).query)['input'] == [key]
            assert parse_qs(urlparse(captured_url).query)['examine'] == [captured_key]
            capture.click()
            page.wait_for_selector('#derivedExamination')
            assert page.locator('#derivedExamination').evaluate('(el) => el === document.activeElement')
            assert 'process.dmp' in page.locator('#derivedExamination').inner_text()
            page.get_by_role('button', name='All captured files', exact=True).click()
            card = page.locator(f'#workspaceTabPanel .evidence-card[data-examine="{captured_key}"]')
            card.wait_for()
            assert card.evaluate('(el) => el === document.activeElement')
            page.keyboard.press('Enter')
            page.wait_for_selector('#derivedExamination')
            page.get_by_role('tab', name='Processes', exact=True).click()
            page.wait_for_selector('#memoryFilters')
            assert page.locator('[name=process_q]').input_value() == 'process-42.exe'
            assert page.locator('.triage-inspector').count() == 1
            count = len(repo.runs())
            page.get_by_role('button', name='Read command line · View result', exact=True).click()
            page.wait_for_selector('.workspace-result-table')
            assert len(repo.runs()) == count
            page.get_by_text('Known indicators', exact=True).click()
            page.get_by_role('button', name='Scan process with YARA rules', exact=True).click()
            rules = source.parent / 'reviewed rules.yar'
            rules.write_text('rule dos_message { strings: $a="DOS mode" condition: $a }')
            rule_field = page.get_by_label('YARA rules file', exact=True)
            assert rule_field.is_visible()
            assert rule_field.input_value() == str(DEFAULT_RULES)
            rule_field.fill(str(rules))
            page.get_by_role('button', name='Run volatility', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            rules_run = parse_qs(urlparse(page.url).query)['run'][0]
            assert '--pid 42' in page.locator('#operationCommand').text_content()
            page.reload()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('progress')")
            page.evaluate("window.memoryDocument = 'same document'")
            worker.run_once()
            page.get_by_role('button', name='Scan process with YARA rules · View result', exact=True).wait_for()
            assert any(record['path'] == str(rules) for record in repo.input(rules_run)['related_files'])
            page.get_by_role('tab', name='Investigate', exact=True).click()
            page.select_option('#memoryQuestion', 'injection')
            page.get_by_role('heading', name='Do executable regions and loaded modules agree?', exact=True).wait_for()
            page.get_by_role('button', name='Inspect potential injection', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.locator('#workspaceReportSearch').wait_for()
            page.locator('[name=report_q]').fill('process-42.exe')
            page.get_by_role('button', name='Search report', exact=True).click()
            page.wait_for_function("document.querySelectorAll('.workspace-result-table tbody tr').length === 1")
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(tmp_path/f'memory-investigate-{width}.png'), full_page=True)
            page.get_by_role('link', name='Review PID 42', exact=True).click()
            page.get_by_role('heading', name='Process 42', exact=True).wait_for()
            page.get_by_role('tab', name='Investigate', exact=True).click()
            page.wait_for_function("document.querySelector('#memoryQuestion')?.value === 'injection'")
            page.select_option('#memoryQuestion', 'persistence')
            page.get_by_role('button', name='Locate registry hives', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.locator('[data-operation-slot="investigation-hives"] [data-workspace-result]').wait_for(state='attached')
            page.get_by_role('button', name='Extract a registry hive', exact=True).click()
            page.get_by_label('Registry hive', exact=True).select_option('SYSTEM')
            page.get_by_role('button', name='Run volatility', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            assert '--filter=SYSTEM' in page.locator('#operationCommand').text_content()
            worker.run_once()
            page.locator('[data-operation-slot="investigation-capture_hives"] [data-workspace-result]').wait_for(state='attached')
            page.get_by_role('tab', name='Prepare', exact=True).click()
            page.select_option('#memoryOS', 'linux')
            page.wait_for_function("JSON.parse(document.querySelector('#workspaceState').textContent).memory_os === 'linux'")
            page.get_by_role('tab', name='Processes', exact=True).click()
            page.get_by_role('heading', name='No process inventory yet').wait_for()
            page.get_by_role('tab', name='Prepare', exact=True).click()
            page.select_option('#memoryOS', 'windows')
            page.wait_for_function("JSON.parse(document.querySelector('#workspaceState').textContent).memory_os === 'windows'")
            page.get_by_role('tab', name='Processes', exact=True).click()
            page.wait_for_selector('#memoryFilters')
            assert page.locator('.triage-inspector').count() == 1
            assert page.evaluate('window.memoryDocument') == 'same document'
            page.get_by_role('button', name='Close process', exact=True).click()
            page.wait_for_function("document.activeElement.dataset.processRow === '43'")
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_evidence_cards_unify_case_hubs_and_analysis(workspace_runtime, tmp_path, width):
    app, client, repo, settings, source, outputs, case, disk_key = workspace_runtime
    worker = Worker(repo, settings)

    def add(name, content, **metadata):
        path = source.parent / name
        path.write_bytes(content)
        response = client.post(f'/api/case/{case}/artifacts', json={'path': str(path), **metadata})
        assert response.status_code == 202
        return response.json['artifact']

    memory = add('memory.raw', b'\0' * 4096, type='memory_dump')
    worker.run_once()
    # The card must follow observed content, as the analysis does, rather than a
    # misleading extension or registered disk type.
    document = add('document.E01', b'%PDF-1.7\n', type='disk_image', label='Report <review> & notes')
    worker.run_once()
    failed = add('mismatched.txt', b'known evidence', expected_sha256='0' * 64)
    worker.run_once()
    retired = add('retired.txt', b'old evidence')
    worker.run_once()
    assert client.delete(f"/api/case/{case}/artifacts/{retired['id']}").status_code == 200
    pending = add('pending.txt', b'pending evidence', label='Pending ' + 'long-evidence-name-' * 10)
    empty_name = 'Empty <case> & notes ' * 6
    client.post('/cases', data={'name': empty_name, 'summary': 'Acquisition notes for review. ' * 20})
    empty_case = repo.cases()[-1]['id']
    run_count = len(repo.runs())
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': width, 'height': 900})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            hub = base + f'/case/{case}/workspace'
            page.goto(base + '/evidence')
            assert page.locator('.case-entry-card').count() == 2
            assert page.locator('.evidence-card, .add-artifact-btn, #addArtifactModal').count() == 0
            case_card = page.locator(f'[data-evidence-case="{case}"]')
            assert '5 evidence items' in case_card.inner_text()  # Retired evidence is excluded.
            assert case_card.get_attribute('href') == f'/case/{case}/workspace'
            empty_card = page.locator(f'[data-evidence-case="{empty_case}"]')
            assert '0 evidence items' in empty_card.inner_text()
            assert empty_name.strip() in empty_card.inner_text()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(tmp_path / f'evidence-case-selection-{width}.png'), full_page=True)
            case_card.focus()
            page.keyboard.press('Enter')
            page.wait_for_url(hub)
            assert page.locator('.evidence-card').count() == 5
            page.go_back()
            page.wait_for_url(base + '/evidence')
            assert page.locator('.case-entry-card').count() == 2
            assert page.locator('.evidence-card').count() == 0
            for route in ['/cases', f'/case/{case}/workspace']:
                page.goto(base + route)
                if route == '/cases':
                    page.locator(f'#case-{case} .case-toggle').click()
                cards = page.locator('.evidence-card')
                assert cards.count() == 5
                assert page.locator(f'[data-evidence-key="e:{retired["id"]}"]').count() == 0
                assert 'Memory image' in page.locator(f'[data-evidence-key="e:{memory["id"]}"]').inner_text()
                pdf = page.locator(f'[data-evidence-key="e:{document["id"]}"]')
                assert 'PDF document' in pdf.inner_text() and 'Report <review> & notes' in pdf.inner_text()
                assert pdf.get_by_role('button').count() == 0  # One accessible link per card.
                assert 'Verification failed' in page.locator(f'[data-evidence-key="e:{failed["id"]}"]').inner_text()
                assert 'Verifying' in page.locator(f'[data-evidence-key="e:{pending["id"]}"]').inner_text()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.screenshot(path=str(tmp_path / f'evidence-{route.split("/")[1]}-{width}.png'), full_page=True)
            assert page.locator('[role=tablist]').count() == 0
            assert len(repo.runs()) == run_count  # Browsing cards never profiles or launches work.
            # Keyboard entry chooses this evidence, and browser Back returns to the hub.
            page.locator(f'[data-evidence-key="e:{memory["id"]}"]').focus()
            page.keyboard.press('Enter')
            page.get_by_role('tab', name='Processes', exact=True).wait_for()
            assert parse_qs(urlparse(page.url).query)['input'] == ['e:' + memory['id']]
            assert 'Memory image' in page.locator('.workspace-header').inner_text()
            page.screenshot(path=str(tmp_path / f'memory-prepare-{width}.png'), full_page=True)
            page.go_back()
            page.locator(f'[data-evidence-key="{disk_key}"]').click()
            page.get_by_role('button', name='Map disk', exact=True).wait_for()
            page.get_by_role('link', name='All evidence', exact=True).click()
            page.locator(f'[data-evidence-key="e:{failed["id"]}"]').click()
            page.get_by_role('button', name='Verify integrity', exact=True).wait_for()
            assert page.get_by_role('button', name='Continue to Analysis').count() == 0
            page.get_by_text('Manage evidence', exact=True).click()
            page.once('dialog', lambda dialog: dialog.accept())
            page.get_by_role('button', name='Retire evidence', exact=True).click()
            page.wait_for_url(hub)
            assert page.locator('.evidence-card').count() == 4
            assert (source.parent / 'mismatched.txt').is_file()
            assert client.get(f"/api/case/{case}/evidence/{failed['id']}/custody").status_code == 200
            page.get_by_role('button', name='Add evidence', exact=True).click()
            page.get_by_role('dialog', name='Add evidence').wait_for()
            assert page.locator('#artifactCaseId').input_value() == case
            page.keyboard.press('Escape')
            assert page.locator('.add-artifact-btn').evaluate('(el) => el === document.activeElement')
            page.goto(base + f'/case/{empty_case}/workspace')
            page.get_by_role('heading', name='No evidence yet').wait_for()
            page.get_by_role('button', name='Add evidence', exact=True).click()
            assert page.locator('#artifactCaseId').input_value() == empty_case
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.browser
@pytest.mark.parametrize('width', [390, 1440])
def test_ambiguous_acquisition_reveals_the_selected_workflow(memory_workspace, width, tmp_path):
    app, client, repo, _, source, case, _, _ = memory_workspace
    settings = app.config['SETTINGS']
    detector = tmp_path / 'filetype.py'
    detector.write_text("print('application/octet-stream')")
    settings.binaries['filetype'] = [sys.executable, str(detector)]
    # Preserve an explicit fallback when neither signatures nor native probes
    # can establish the acquisition; the filename cannot make that decision.
    raw = tmp_path / 'unclassified-capture.data'
    raw.write_bytes(b'\0' * 4096)
    response = client.post(f'/api/case/{case}/artifacts', json={'path': str(raw)})
    assert response.status_code == 202
    artifact = response.json['artifact']
    key = 'e:' + artifact['id']
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
            page = browser.new_page(viewport={'width': width, 'height': 900})
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + f'/case/{case}/workspace?' + urlencode({'input': key}))
            assert page.locator('#evidenceTypeForm').count() == 0  # Intake first.
            worker.run_once()
            page.get_by_role('heading', name='Set evidence type', exact=True).wait_for()
            assert page.get_by_role('button', name='Continue to Analysis').count() == 0
            original = repo.case(case)['artifacts'][-1]
            page.get_by_role('link', name='All evidence', exact=True).click()
            card = page.locator(f'[data-evidence-key="{key}"]')
            assert 'Acquisition type needed' in card.inner_text() and 'Set type' in card.inner_text()
            card.click()
            page.get_by_role('heading', name='Set evidence type', exact=True).wait_for()
            assert page.get_by_role('tab', name='Processes', exact=True).count() == 0
            assert page.locator('[data-workspace-tool]').first.is_hidden()
            assert page.get_by_label('Acquisition type', exact=True).input_value() == ''
            page.evaluate("window.acquisitionDocument = 'retained'")
            page.screenshot(path=str(tmp_path / f'acquisition-choice-{width}.png'), full_page=True)
            count = len(repo.runs())
            page.get_by_label('Acquisition type', exact=True).select_option('memory_dump')
            # A failed save keeps the choice available and does not change custody.
            page.route('**/evidence/*/type', lambda route: route.fulfill(status=503, json={'error': 'Storage temporarily unavailable'}), times=1)
            page.get_by_role('button', name='Continue', exact=True).click()
            page.wait_for_function("document.querySelector('#workspaceStatus').textContent.includes('Storage temporarily unavailable')")
            assert page.get_by_label('Acquisition type', exact=True).input_value() == 'memory_dump'
            assert repo.case(case)['artifacts'][-1]['type_basis'] == 'content'
            page.get_by_role('button', name='Continue', exact=True).click()
            page.get_by_role('button', name='Identify image', exact=True).wait_for()
            assert page.get_by_role('tab', name='Processes', exact=True).count() == 1
            assert page.get_by_role('tab', name='Investigate', exact=True).count() == 1
            assert page.locator('#evidenceTypeForm').count() == 0
            assert page.locator('#workspaceTabPanel').evaluate('(el) => el === document.activeElement')
            current = repo.case(case)['artifacts'][-1]
            assert current['hash'] == original['hash'] and current['profile'] == original['profile']
            assert len(repo.runs()) == count  # Choosing context never launches analysis.
            page.reload()
            page.get_by_role('button', name='Identify image', exact=True).wait_for()
            page.get_by_role('button', name='Identify image', exact=True).click()
            page.wait_for_function("document.querySelector('#operationStatus').textContent.includes('Queued')")
            worker.run_once()
            page.get_by_role('button', name='Build process inventory', exact=True).wait_for()
            page.get_by_role('tab', name='Overview', exact=True).click()
            page.get_by_role('button', name='Verify integrity', exact=True).click()
            page.wait_for_function("document.querySelector('#workspaceTabPanel').textContent.includes('Verifying')")
            worker.run_once()
            page.get_by_role('button', name='Verify integrity', exact=True).wait_for()
            assert page.get_by_role('heading', name='Set evidence type', exact=True).count() == 0
            assert repo.case(case)['artifacts'][-1]['type'] == 'memory_dump'
            page.evaluate("window.acquisitionDocument = 'retained'")
            for value, label in [('disk_image', 'File triage'), ('artifact_file', 'Analysis')]:
                page.get_by_text('Manage evidence', exact=True).click()
                page.get_by_label('Acquisition type', exact=True).select_option(value)
                page.get_by_role('button', name='Save type', exact=True).click()
                page.get_by_role('tab', name=label, exact=True).wait_for()
                assert page.get_by_role('tab', name='Processes', exact=True).count() == 0
                assert page.locator('#workspaceOperation').is_hidden()
                assert not any(param in page.url for param in ('run=', 'memory_os=', 'context_run_id='))
                page.get_by_role('tab', name='Overview', exact=True).click()
            page.get_by_role('tab', name='Analysis', exact=True).click()
            page.get_by_role('heading', name='Examine evidence', exact=True).wait_for()
            assert page.locator('#evidenceTypeForm').is_hidden()
            assert page.evaluate('window.acquisitionDocument') == 'retained'
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
