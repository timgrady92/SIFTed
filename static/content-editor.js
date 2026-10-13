(() => {
  'use strict';
  const reference = window.SiftedReference;
  const config = JSON.parse(document.getElementById('referenceEditorConfig').textContent);
  const $ = id => document.getElementById(id);
  const escape = reference.escape;
  const form = $('referenceEditor'), kind = $('contentKind'), section = $('contentSection'), category = $('contentCategory');
  const body = $('guideBody'), status = $('editorStatus');
  const listFields = new Set(['corroborate', 'location', 'keyFields']);
  const rowFields = {databases: ['file', 'tables', 'timestamps'], eventLogs: ['id', 'log', 'meaning']};
  let entry = config.entry, dirty = false, lastRange = null, saving = false;
  const params = new URL(location.href).searchParams;
  const copied = reference.get(params.get('copy'));
  let draft = entry || copied;
  kind.value = draft?.kind || (params.get('kind') === 'guide' ? 'guide' : 'glossary');
  const titleField = () => kind.value === 'guide' ? 'title' : section.value === 'registry' ? 'key' : section.value === 'persistence' ? 'path' : 'name';
  function template(type) {
    if (type === 'artifact') return ['What this artifact contains', 'Questions it can answer', 'How to examine it', 'Evidence to corroborate', 'Pitfalls and limitations'].map(label => `<div class="guide-section"><h3>${label}</h3><p><br></p></div>`).join('');
    const part = (label, list = false, warning = false) => `<div class="guide-detail-section"><div class="guide-detail-label${warning ? ' warning' : ''}">${label}</div>${list ? '<ul class="guide-detail-list"><li><br></li></ul>' : '<p class="guide-detail-text"><br></p>'}</div>`;
    return `<div class="guide-group"><div class="guide-group-header">Framing</div>${part('The hypothesis')}${part('Key questions', true)}</div><div class="guide-group"><div class="guide-group-header">Evidence</div>${part('Evidence sources', true)}</div><div class="guide-group"><div class="guide-group-header">Analysis</div>${part('Corroboration', true)}${part('Pitfalls', true, true)}${part('Limitations', true, true)}${part('When to stop')}</div>`;
  }
  function addRow(field, group = '', values = {}) {
    const row = document.createElement('div');
    row.className = 'reference-detail-row';
    row.dataset.detailRow = field;
    row.innerHTML = `<label>Group<input data-column="group" value="${escape(group)}" maxlength="120" required></label>` + rowFields[field].map(key => `<label>${escape(key[0].toUpperCase()+key.slice(1))}<input data-column="${key}" value="${escape(values[key] || '')}" required></label>`).join('') + '<button class="ghost" type="button" data-remove-row aria-label="Remove detail row">Remove</button>';
    $(field === 'databases' ? 'databaseRows' : 'eventRows').append(row);
  }
  function initialize(data = {}, selectedSection, selectedCategory) {
    const guide = kind.value === 'guide';
    const sections = guide ? {hypothesis:'Hypothesis driven', artifact:'Artifact driven'} : config.sections;
    section.innerHTML = Object.entries(sections).map(([id,name]) => `<option value="${id}">${escape(name)}</option>`).join('');
    section.value = selectedSection && sections[selectedSection] ? selectedSection : Object.keys(sections)[0];
    const categories = reference.catalog.categories[guide ? 'guides' : section.value];
    category.innerHTML = Object.entries(categories).map(([id,name]) => `<option value="${id}">${escape(name)}</option>`).join('');
    category.value = selectedCategory && categories[selectedCategory] ? selectedCategory : 'custom';
    $('editorHeading').textContent = `${entry ? 'Edit' : 'New'} ${guide ? 'guide' : 'glossary entry'}`;
    $('editorBack').href = guide ? '/guides' : '/glossary';
    $('guideAuthoring').hidden = !guide;
    $('contentOS').hidden = guide || section.value !== 'artifacts';
    $('contentAdvanced').hidden = guide || section.value !== 'artifacts';
    const fields = config.fields[guide ? 'guide' : section.value];
    $('contentFields').innerHTML = fields.map(([key,label]) => {
      const multiline = listFields.has(key) || ['what','why','lookFor','notes','description'].includes(key);
      const value = listFields.has(key) ? (data[key] || []).join('\n') : data[key] || '';
      const required = !listFields.has(key) && !['keywords','question'].includes(key);
      return `<label class="${multiline ? 'reference-wide' : ''}">${escape(label)}${multiline ? `<textarea data-field="${key}" rows="${listFields.has(key) ? 3 : 2}" maxlength="8000" ${required ? 'required' : ''}>${escape(value)}</textarea>` : `<input data-field="${key}" maxlength="8000" value="${escape(value)}" ${required ? 'required' : ''}>`}${listFields.has(key) ? '<span class="helper">One item per line.</span>' : ''}</label>`;
    }).join('');
    form.querySelectorAll('[name="os"]').forEach(el => { el.checked = (data.os || ['windows']).includes(el.value); });
    for (const field of Object.keys(rowFields)) {
      $(field === 'databases' ? 'databaseRows' : 'eventRows').replaceChildren();
      Object.entries(data[field] || {}).forEach(([group, rows]) => rows.forEach(row => addRow(field, group, row)));
    }
    body.innerHTML = guide ? data.body || template(section.value) : '';
    kind.disabled = !!entry;
    section.disabled = !!entry;
    $('editorPreview').hidden = true;
  }
  initialize(draft?.data, draft?.section, draft?.category);
  if (copied && !entry) {
    const input = form.querySelector(`[data-field="${titleField()}"]`);
    if (input) input.value += ' (copy)';
    dirty = true;
  }
  let previousKind = kind.value, previousSection = section.value;
  function changeType() {
    if (dirty && !confirm('Changing the content type replaces this unsaved draft. Continue?')) {
      kind.value = previousKind; section.value = previousSection; return;
    }
    initialize({}, kind.value === previousKind ? section.value : null);
    previousKind = kind.value; previousSection = section.value;
    dirty = false; status.textContent = '';
  }
  kind.addEventListener('change', changeType);
  section.addEventListener('change', changeType);
  form.addEventListener('input', event => {
    if (event.target === kind || event.target === section) return;
    dirty = true; status.textContent = 'Unsaved changes.';
  });
  form.addEventListener('change', event => { if (event.target !== kind && event.target !== section) dirty = true; });
  window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
  document.addEventListener('selectionchange', () => {
    const selection = getSelection();
    if (selection.rangeCount && body.contains(selection.anchorNode) && body.contains(selection.focusNode)) lastRange = selection.getRangeAt(0).cloneRange();
  });
  function restoreSelection() {
    body.focus();
    const selection = getSelection();
    const range = lastRange && body.contains(lastRange.commonAncestorContainer) ? lastRange : document.createRange();
    if (range !== lastRange) { range.selectNodeContents(body); range.collapse(false); }
    selection.removeAllRanges(); selection.addRange(range);
  }
  function insert(html, preserveAttributes = false) {
    restoreSelection();
    if (preserveAttributes) {
      // Chromium can rewrite inserted inline spans and drop their stable glossary IDs.
      const selection = getSelection(), range = selection.getRangeAt(0);
      const fragment = range.createContextualFragment(html), end = fragment.lastChild;
      range.deleteContents(); range.insertNode(fragment);
      range.setStartAfter(end); range.collapse(true);
      selection.removeAllRanges(); selection.addRange(range);
      lastRange = range.cloneRange();
    } else document.execCommand('insertHTML', false, html);
    dirty = true;
  }
  document.querySelector('.reference-toolbar').addEventListener('mousedown', event => { if (event.target.closest('button')) event.preventDefault(); });
  form.addEventListener('click', event => {
    const format = event.target.closest('[data-format], [data-block]');
    if (format) { restoreSelection(); document.execCommand(format.dataset.format || 'formatBlock', false, format.dataset.block || null); dirty = true; }
    const add = event.target.closest('[data-add-row]');
    if (add) { addRow(add.dataset.addRow); dirty = true; }
    const remove = event.target.closest('[data-remove-row]');
    if (remove) { remove.closest('[data-detail-row]').remove(); dirty = true; }
  });
  // Paste as text: rich content is introduced through the constrained formatting controls.
  body.addEventListener('paste', event => { event.preventDefault(); restoreSelection(); document.execCommand('insertText', false, event.clipboardData.getData('text/plain')); dirty = true; });
  body.addEventListener('drop', event => event.preventDefault());
  $('insertGuideSection').addEventListener('click', () => insert('<div class="guide-section"><h3>Section title</h3><p>Write this section.</p></div>'));
  $('insertGuideTable').addEventListener('click', () => insert('<table><thead><tr><th>Evidence</th><th>Interpretation</th></tr></thead><tbody><tr><td>Artifact</td><td>What it may indicate</td></tr></tbody></table><p><br></p>'));

  function populateLinks() {
    const query = $('referenceLinkSearch').value.toLowerCase();
    const records = reference.catalog.records.filter(entry => entry.kind === 'glossary' && `${entry.title} ${entry.what}`.toLowerCase().includes(query));
    $('referenceLinkChoices').innerHTML = records.map(entry => `<option value="${escape(entry.id)}">${escape(entry.title)} — ${escape(config.sections[entry.section])}</option>`).join('');
    $('confirmReferenceLink').disabled = records.length === 0;
    if (records.length) { $('referenceLinkChoices').selectedIndex = 0; $('referenceLinkText').value = records[0].title; }
    else $('referenceLinkText').value = '';
  }
  $('insertGlossaryLink').addEventListener('click', async () => {
    $('referenceLinkStatus').textContent = '';
    try { await reference.refresh(); } catch (error) { $('referenceLinkStatus').textContent = error.message; }
    $('referenceLinkSearch').value = ''; populateLinks(); $('referenceLinkPicker').showModal(); $('referenceLinkSearch').focus();
  });
  $('referenceLinkSearch').addEventListener('input', populateLinks);
  $('referenceLinkChoices').addEventListener('change', () => { $('referenceLinkText').value = reference.get($('referenceLinkChoices').value)?.title || ''; });
  $('confirmReferenceLink').addEventListener('click', () => {
    const target = reference.get($('referenceLinkChoices').value);
    if (!target) return;
    const text = $('referenceLinkText').value.trim() || target.title;
    $('referenceLinkPicker').close();
    insert(`<span class="artifact-link" data-artifact="${escape(target.id)}" role="link" tabindex="0">${escape(text)}</span> `, true);
  });
  $('insertWebLink').addEventListener('click', () => { $('referenceWebLink').showModal(); $('webLinkText').focus(); });
  $('cancelWebLink').addEventListener('click', () => $('referenceWebLink').close());
  $('webLinkForm').addEventListener('submit', event => {
    event.preventDefault();
    let url;
    try { url = new URL($('webLinkURL').value); }
    catch { $('webLinkStatus').textContent = 'Enter a complete HTTP or HTTPS URL.'; return; }
    if (!['http:', 'https:'].includes(url.protocol)) { $('webLinkStatus').textContent = 'Use an HTTP or HTTPS URL.'; return; }
    $('referenceWebLink').close();
    insert(`<a href="${escape(url.href)}" rel="noopener noreferrer">${escape($('webLinkText').value)}</a>`);
  });

  function payload() {
    const data = {};
    form.querySelectorAll('[data-field]').forEach(input => { data[input.dataset.field] = listFields.has(input.dataset.field) ? input.value.split('\n').map(v => v.trim()).filter(Boolean) : input.value; });
    if (kind.value === 'guide') data.body = body.innerHTML;
    else if (section.value === 'artifacts') {
      data.os = [...form.querySelectorAll('[name="os"]:checked')].map(el => el.value);
      for (const field of Object.keys(rowFields)) {
        data[field] = Object.create(null);
        form.querySelectorAll(`[data-detail-row="${field}"]`).forEach(row => {
          const group = row.querySelector('[data-column="group"]').value.trim();
          const values = Object.fromEntries(rowFields[field].map(key => [key, row.querySelector(`[data-column="${key}"]`).value]));
          (data[field][group] ||= []).push(values);
        });
      }
    }
    return {kind: kind.value, section: section.value, category: category.value, data, revision: entry?.revision || 0};
  }
  async function submit(preview) {
    if (saving || !form.reportValidity()) return;
    saving = true; $('saveContent').disabled = true; $('previewContent').disabled = true;
    status.textContent = preview ? 'Preparing preview…' : 'Saving…';
    const draft = payload();
    try {
      const url = preview ? '/api/reference/preview' : '/api/reference' + (entry ? '/' + encodeURIComponent(entry.id) : '');
      const response = await fetch(url, {method: preview || !entry ? 'POST' : 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(draft)});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Unable to save content. Your draft is still here.');
      if (preview) {
        $('editorPreviewBody').innerHTML = (result.entry.kind === 'guide' ? `<h3>${escape(result.entry.title)}</h3>` : '') + result.entry.html;
        $('editorPreview').hidden = false;
        status.textContent = 'Preview ready. Changes are not saved yet.';
      } else {
        entry = result.entry;
        // Edits made during the request remain an unsaved draft.
        const now = payload(); delete now.revision; const sent = {...draft}; delete sent.revision;
        dirty = JSON.stringify(now) !== JSON.stringify(sent);
        kind.disabled = true; section.disabled = true;
        history.replaceState(null, '', `/reference/${entry.id}/edit`);
        const link = $('viewSavedContent'); link.href = `/${entry.kind === 'guide' ? 'guides' : 'glossary'}?entry=${encodeURIComponent(entry.id)}`; link.hidden = false;
        $('editorHeading').textContent = `Edit ${entry.kind === 'guide' ? 'guide' : 'glossary entry'}`;
        status.textContent = dirty ? 'Saved. Your newer changes still need to be saved.' : 'Saved. Available in the library, sidebars and glossary link picker.';
        try { await reference.refresh(true); } catch { status.textContent += ' Reload the library to refresh its content.'; }
      }
    } catch (error) { status.textContent = error.message; }
    finally { saving = false; $('saveContent').disabled = false; $('previewContent').disabled = false; }
  }
  form.addEventListener('submit', event => { event.preventDefault(); submit(false); });
  $('previewContent').addEventListener('click', () => submit(true));
})();
