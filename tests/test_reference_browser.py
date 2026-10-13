"""Author and link real content through the UI, including updates in already-open tabs."""
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app import create_app

playwright = pytest.importorskip('playwright.sync_api')


@pytest.mark.browser
@pytest.mark.parametrize('width', [1440, 390])
def test_authoring_shared_search_and_post_install_tooltips(tmp_path, width):
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'reference.db'),
                      'SIFTED_INPUT_ROOTS': [str(tmp_path)], 'SIFTED_OUTPUT_ROOTS': [str(tmp_path)]})
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with playwright.sync_playwright() as engine:
            if not Path(engine.chromium.executable_path).is_file():
                pytest.skip('Chromium is not installed.')
            browser = engine.chromium.launch(headless=True)
            context = browser.new_context(viewport={'width': width, 'height': 1000})
            library, editor, guide_editor = [context.new_page() for _ in range(3)]
            for page in (library, editor, guide_editor):
                page.on('pageerror', lambda error: errors.append(str(error)))
            library.goto(base + '/guides')
            library.fill('#guideSearch', 'Zephyr audit investigation')
            editor.goto(base + '/glossary')
            editor.get_by_role('link', name='New glossary entry', exact=True).click()
            for name, value in {'name':'Zephyr audit records', 'takeaway':'A local cloud audit trail.',
                                'what':'Locally cached Zephyr cloud activity.', 'why':'Corroborates provider activity.',
                                'question':'Which account accessed the tenant?', 'location':'/cases/zephyr/cache.db',
                                'corroborate':'Provider sign-in logs'}.items():
                editor.locator(f'[data-field="{name}"]').fill(value)
            editor.get_by_role('button', name='Save content', exact=True).click()
            editor.wait_for_url('**/reference/user-*/edit')
            glossary_id = editor.url.split('/')[-2]
            editor.wait_for_function("document.querySelector('#editorStatus').textContent.startsWith('Saved.')")
            assert editor.evaluate('document.documentElement.scrollWidth <= innerWidth')

            guide_editor.goto(base + '/guides')
            guide_editor.get_by_role('link', name='New guide', exact=True).click()
            # Choosing a starter format on a blank draft must not discard or block the choice.
            guide_editor.select_option('#contentSection', 'artifact')
            assert guide_editor.locator('#guideBody .guide-section').count() == 5
            guide_editor.select_option('#contentSection', 'hypothesis')
            assert guide_editor.locator('#guideBody .guide-group').count() == 3
            for name, value in {'title':'Zephyr audit investigation', 'description':'Compare local and remote access evidence.',
                                'keywords':'zephyr cloud audit'}.items():
                guide_editor.locator(f'[data-field="{name}"]').fill(value)
            guide_editor.locator('#guideBody .guide-detail-text').first.fill('Test whether cloud access was authorized.')
            guide_editor.locator('#guideBody .guide-detail-list li').first.fill('Could this be routine administrative access?')
            guide_editor.locator('#guideBody .guide-detail-text').first.evaluate('''node => {
                const range = document.createRange(); range.selectNodeContents(node);
                const selection = getSelection(); selection.removeAllRanges(); selection.addRange(range);
            }''')
            guide_editor.get_by_role('button', name='Bold', exact=True).click()
            assert guide_editor.locator('#guideBody b, #guideBody strong').count() == 1
            guide_editor.locator('#guideBody .guide-detail-text').last.click()
            guide_editor.get_by_role('button', name='Add table', exact=True).click()
            guide_editor.locator('#guideBody td').first.fill('Cache evidence')
            guide_editor.get_by_role('button', name='Insert web link', exact=True).click()
            guide_editor.locator('#webLinkText').fill('Collection documentation')
            guide_editor.locator('#webLinkURL').fill('https://example.org/collection')
            guide_editor.locator('#webLinkForm').get_by_role('button', name='Insert link', exact=True).click()
            guide_editor.locator('#guideBody .guide-detail-text').first.click()
            guide_editor.keyboard.press('End')
            guide_editor.get_by_role('button', name='Insert glossary link', exact=True).click()
            guide_editor.fill('#referenceLinkSearch', 'Zephyr')
            guide_editor.wait_for_function("document.querySelector('#referenceLinkChoices').options.length === 1")
            guide_editor.get_by_role('button', name='Insert link', exact=True).click()
            assert guide_editor.locator(f'#guideBody [data-artifact="{glossary_id}"]').count() == 1
            guide_editor.get_by_role('button', name='Preview', exact=True).click()
            preview_link = guide_editor.locator(f'#editorPreview [data-artifact="{glossary_id}"]')
            preview_link.wait_for()
            assert guide_editor.locator('#editorPreview table').inner_text().find('Cache evidence') >= 0
            assert guide_editor.locator('#editorPreview a[href="https://example.org/collection"]').count() == 1
            preview_link.hover()
            assert 'Locally cached Zephyr cloud activity.' in guide_editor.locator('#artifactTooltip').inner_text()
            guide_editor.get_by_role('button', name='Save content', exact=True).click()
            guide_editor.wait_for_url('**/reference/user-*/edit')
            guide_id = guide_editor.url.split('/')[-2]
            guide_editor.wait_for_function("document.querySelector('#editorStatus').textContent.startsWith('Saved.')")
            assert guide_editor.evaluate('document.documentElement.scrollWidth <= innerWidth')

            # This library was opened before either record existed.
            button = library.locator(f'[data-reference-guide="{guide_id}"]')
            button.wait_for()
            button.click()
            assert library.locator('#guideModalTitle').inner_text() == 'Zephyr audit investigation'
            assert 'Cache evidence' in library.locator('#guideModalBody table').inner_text()
            link = library.locator(f'#guideModalBody [data-artifact="{glossary_id}"]')
            link.hover()
            library.locator('#artifactTooltip.visible').wait_for()
            assert 'Locally cached Zephyr cloud activity.' in library.locator('#artifactTooltip').inner_text()
            link.click()
            sidebar = library.locator('[data-glossary-surface="sidebar"]')
            assert sidebar.get_attribute('aria-hidden') == 'false'
            assert 'Zephyr audit records' in sidebar.locator('[data-glossary-detail-content]').inner_text()
            sidebar.locator('[data-glossary-close]').click()
            library.locator('#guideModalClose').click()
            library.locator('[data-guides-toggle]').click()
            guides = library.locator('[data-guides-surface="sidebar"]')
            guides.locator('[data-guides-search]').fill('Zephyr')
            guides.locator(f'[data-sidebar-guide-id="{guide_id}"]').click()
            assert 'Zephyr audit investigation' in guides.locator('[data-guides-detail-content]').inner_text()
            assert guides.locator(f'[data-guides-detail-content] [data-artifact="{glossary_id}"]').count() == 1
            guides.locator('[data-guides-close]').click()

            # A definition edit changes existing guide tooltips without changing their stable link ID.
            editor.locator('[data-field="what"]').fill('Revised Zephyr definition after installation.')
            editor.get_by_role('button', name='Save content', exact=True).click()
            editor.wait_for_function("document.querySelector('#editorStatus').textContent.startsWith('Saved.')")
            library.wait_for_function("id => window.SiftedReference.get(id).data.what === 'Revised Zephyr definition after installation.'", arg=glossary_id)
            library.goto(base + '/guides?entry=' + guide_id)
            link = library.locator(f'#guideModalBody [data-artifact="{glossary_id}"]')
            link.focus()
            library.locator('#artifactTooltip.visible').wait_for()
            assert 'Revised Zephyr definition after installation.' in library.locator('#artifactTooltip').inner_text()
            library.keyboard.press('Escape')
            library.goto(base + '/glossary?entry=' + glossary_id)
            assert 'Revised Zephyr definition after installation.' in library.locator('.glossary-page [data-glossary-detail-content]').inner_text()
            assert library.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
