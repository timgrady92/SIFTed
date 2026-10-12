(() => {
  'use strict';
  const root = document.querySelector('[data-workspace-case]');
  if (!root) return;
  const caseId = root.dataset.workspaceCase;
  const view = document.getElementById('workspaceView');
  const panel = document.getElementById('workspaceOperation');
  const status = document.getElementById('workspaceStatus');
  const operationStatus = document.getElementById('operationStatus');
  const fields = document.getElementById('operationFields');
  const options = document.getElementById('operationOptions');
  const runButton = document.getElementById('runOperation');
  const cancelButton = document.getElementById('cancelOperation');
  const copyButton = document.getElementById('copyOperation');
  const command = document.getElementById('operationCommand');
  const result = document.getElementById('operationResult');
  const active = new Map();
  let operation = null, busy = false, rendering = 0, previewVersion = 0, resultVersion = 0;
  let polling = false, needsRefresh = false, previewTimer, tabs = {};
  const state = () => JSON.parse(document.getElementById('workspaceState').textContent);
  const inputKey = () => state().input;
  const savedKey = () => `sifted-workspace:${caseId}:${inputKey()}:${state().memory_os || ''}`;
  const at = (attribute, value) => `[${attribute}="${CSS.escape(String(value))}"]`;
  const scopeKey = () => state().tab === 'derived' ? state().examine
    : state().tab === 'triage' ? state().context
    : state().tab === 'investigate' ? `${state().memory_os}:${state().memory_question}`
    : state().tab === 'processes' ? `${state().memory_os}:${state().inventory}` : state().memory_os || '';
  const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
  function matchesAction(job, tool, values, specs = []) {
    if (job.tool !== tool || job.payload?.source_path !== values.source_path) return false;
    const actual = structuredClone(job.payload);
    for (const spec of specs) {
      const path = spec.path || [spec.name], name = path.at(-1);
      if (path.reduce((obj, key) => obj?.[key], values) === undefined) {
        const target = path.slice(0, -1).reduce((obj, key) => obj?.[key], actual);
        if (target) delete target[name];
      }
    }
    return Object.entries(values).filter(([key]) => !['case_id', 'source_path', 'output_path', 'workspace_input'].includes(key))
      .every(([name, value]) => canonical(actual[name] ?? (name === 'tool_id' ? actual.parser_id : '') ?? '') === canonical(value ?? ''));
  }
  function mountOperation() {
    const host = operation && view.querySelector(at('data-operation-slot', operation.slot));
    panel.hidden = !host || operation.dismissed || operation.tab !== state().tab || operation.scope !== scopeKey();
    if (host && !panel.hidden) host.append(panel); else root.append(panel);
  }
  function loadTabs() {
    try { tabs = JSON.parse(sessionStorage.getItem(savedKey()) || '{}'); } catch (_) { tabs = {}; }
  }
  function saveTab() {
    tabs[state().tab] = {search: location.search, scroll: window.scrollY};
    try { sessionStorage.setItem(savedKey(), JSON.stringify(tabs)); } catch (_) { /* Storage may be disabled. */ }
  }
  function announce(message, error = false) {
    status.textContent = message;
    status.dataset.tone = error ? 'error' : '';
  }
  async function json(url, requestOptions) {
    const response = await fetch(url, requestOptions);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The request could not be completed.');
    return data;
  }
  const post = (url, payload) => json(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
  function endpoint(suffix, url = new URL(location.href)) {
    return `/api/case/${encodeURIComponent(caseId)}/workspace${suffix}${url.search}`;
  }
  function seedActive(jobs) {
    for (const job of jobs) if (!active.has(job.runId)) active.set(job.runId, {...job, input: inputKey()});
  }
  function focusSelector(element) {
    if (!element || element === document.body) return null;
    if (element.id) return '#' + CSS.escape(element.id);
    for (const name of ['data-inspect-entry', 'data-process-row', 'data-workspace-tab', 'data-examine', 'data-workspace-result']) {
      if (element.hasAttribute(name)) return at(name, element.getAttribute(name));
    }
    if (element.dataset.workspaceTool) {
      const slot = element.closest('[data-operation-slot]');
      return (slot ? at('data-operation-slot', slot.dataset.operationSlot) + ' ' : '') + at('data-workspace-tool', element.dataset.workspaceTool);
    }
    if (element.name) return at('name', element.name);
    return null;
  }
  function viewport() {
    const anchor = [...view.querySelectorAll('[data-triage-entry], [data-process-entry], [data-operation-slot]')]
      .find(element => element.getBoundingClientRect().top <= 180 && element.getBoundingClientRect().bottom > 180);
    return {scroll: window.scrollY, focus: focusSelector(document.activeElement), operationFocus: panel.contains(document.activeElement),
      anchor: anchor ? at(anchor.hasAttribute('data-triage-entry') ? 'data-triage-entry' : anchor.hasAttribute('data-process-entry') ? 'data-process-entry' : 'data-operation-slot',
        anchor.dataset.triageEntry || anchor.dataset.processEntry || anchor.dataset.operationSlot) : null,
      top: anchor?.getBoundingClientRect().top,
      disclosures: new Map([...view.querySelectorAll('[data-disclosure]')].map(element => [element.dataset.disclosure, element.open]))};
  }
  async function render(url = new URL(location.href), historyMode = '', navigation = {}) {
    const version = ++rendering;
    view.setAttribute('aria-busy', 'true');
    try {
      const data = await json(endpoint('/view', url));
      if (version !== rendering) return false;
      const previous = viewport(), previousTab = state().tab, previousInput = inputKey(), previousScope = scopeKey(), previousOS = state().memory_os;
      const draft = navigation.background && view.querySelector('#triageFilters, #memoryFilters');
      const draftValues = draft ? new FormData(draft) : null;
      const selection = draft?.contains(document.activeElement) && document.activeElement.tagName === 'INPUT'
        ? [document.activeElement.selectionStart, document.activeElement.selectionEnd] : null;
      if (historyMode === 'push') history.pushState(null, '', url);
      if (historyMode === 'replace') history.replaceState(null, '', url);
      // Detach the live form before replacing the fragment, then put it back beside
      // its originating filesystem, file entry or examination. Polling never scrolls.
      root.append(panel);
      view.innerHTML = data.html;
      if (inputKey() !== previousInput) {
        operation = null;
        ++previewVersion;
        ++resultVersion;
        active.clear();
        loadTabs();
      } else if (state().memory_os !== previousOS) {
        operation = null;
        ++previewVersion;
        ++resultVersion;
        loadTabs();
      }
      const sameView = previousInput === inputKey() && previousTab === state().tab && previousScope === scopeKey();
      if (sameView) for (const element of view.querySelectorAll('[data-disclosure]')) {
        if (previous.disclosures.has(element.dataset.disclosure)) element.open = previous.disclosures.get(element.dataset.disclosure);
      }
      mountOperation();
      seedActive(data.active);
      if (sameView && draftValues) for (const [name, value] of draftValues) {
        const field = view.querySelector(`#${draft.id} ${at('name', name)}`);
        if (field) field.value = value;
      }
      const focus = navigation.focus || (sameView ? previous.focus : null);
      if (focus) view.querySelector(focus)?.focus({preventScroll: true});
      if (sameView && previous.operationFocus && panel.hidden) {
        const host = view.querySelector(at('data-operation-slot', operation?.slot || ''));
        const next = host?.querySelector('.workspace-next .action, [data-examine], [data-workspace-tool]')
          || view.querySelector('.workspace-next .action') || view.querySelector('#workspaceTabPanel');
        next?.focus({preventScroll: true});
      }
      if (sameView && selection && document.activeElement.type === 'search') document.activeElement.setSelectionRange(...selection);
      revealActiveTab();
      const anchor = sameView && previous.anchor && view.querySelector(previous.anchor);
      let scroll = anchor ? window.scrollY + anchor.getBoundingClientRect().top - previous.top : previous.scroll;
      if (!sameView) scroll = navigation.scroll ?? Math.min(previous.scroll, view.querySelector('.workspace-tabs')?.offsetTop || 0);
      window.scrollTo({top: scroll, behavior: 'instant'});
      saveTab();
      announce('');
      return true;
    } catch (error) {
      if (version === rendering) announce(error.message, true);
      return false;
    } finally { if (version === rendering) view.removeAttribute('aria-busy'); }
  }
  function revealActiveTab() {
    const bar = view.querySelector('.workspace-tabs'), selected = bar?.querySelector('[aria-selected="true"]');
    if (!selected) return;
    const bounds = bar.getBoundingClientRect(), tabBounds = selected.getBoundingClientRect();
    if (tabBounds.right > bounds.right) bar.scrollLeft += tabBounds.right - bounds.right;
    else if (tabBounds.left < bounds.left) bar.scrollLeft -= bounds.left - tabBounds.left;
  }
  async function navigate(url, navigation = {}) {
    saveTab();
    if (url.search !== location.search) url.searchParams.delete('run');
    await render(url, 'push', navigation);
  }
  async function tab(name, changes = {}, focus = false) {
    saveTab();
    const url = new URL(location.href);
    const saved = new URLSearchParams(tabs[name]?.search || '');
    for (const key of ['context_run_id', 'directory', 'q', 'kind', 'state', 'scope', 'offset', 'examine', 'entry', 'run', 'inventory_run_id', 'process_q', 'process_offset', 'process_row', 'memory_question']) {
      url.searchParams.delete(key);
      if (saved.has(key) && key !== 'run') url.searchParams.set(key, saved.get(key));
    }
    url.searchParams.set('tab', name);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) url.searchParams.delete(key); else url.searchParams.set(key, value);
    }
    await render(url, 'push', {scroll: tabs[name]?.scroll, focus: typeof focus === 'string' ? focus : focus ? `#tab-${name}` : null});
  }
  function payload() {
    const data = structuredClone(operation.payload);
    for (const field of fields.querySelectorAll('[data-field]')) {
      const path = JSON.parse(field.dataset.path), name = path.pop();
      const target = path.reduce((obj, key) => obj[key] ??= {}, data);
      if (field.type === 'checkbox') target[name] = field.checked;
      else if (field.value !== '') target[name] = field.dataset.valueType === 'number' ? Number(field.value) : field.value;
      else delete target[name];
    }
    return data;
  }
  function buildFields(specs, values) {
    fields.replaceChildren();
    for (const spec of specs) {
      const label = document.createElement('label');
      label.append(document.createTextNode(spec.label));
      const field = document.createElement(spec.type === 'select' ? 'select' : 'input');
      field.setAttribute('aria-label', spec.label);
      field.dataset.field = spec.name;
      field.dataset.path = JSON.stringify(spec.path || [spec.name]);
      field.required = Boolean(spec.required);
      field.dataset.valueType = spec.type === 'number' || (spec.type === 'select' && spec.choices.some(([value]) => typeof value === 'number')) ? 'number' : 'text';
      if (spec.type === 'select') {
        for (const [value, text] of spec.choices) field.add(new Option(text, value));
      } else field.type = spec.type;
      if (spec.min !== undefined) field.min = spec.min;
      if (spec.max !== undefined) field.max = spec.max;
      if (spec.placeholder) field.placeholder = spec.placeholder;
      const value = (spec.path || [spec.name]).reduce((obj, key) => obj?.[key], values) ?? spec.default;
      if (spec.type === 'checkbox') field.checked = Boolean(value); else field.value = value ?? '';
      label.append(field);
      fields.append(label);
    }
    options.hidden = !specs.length;
  }
  async function preview() {
    if (!operation || operation.runId) return false;
    const version = ++previewVersion, target = operation;
    runButton.disabled = true;
    copyButton.disabled = true;
    if ([...fields.querySelectorAll('[required]')].some(field => !field.checkValidity())) {
      command.textContent = '';
      operationStatus.textContent = 'Complete the required options to prepare this examination.';
      operationStatus.dataset.tone = '';
      return false;
    }
    try {
      const data = await post(`/api/${target.tool}/preview`, payload());
      if (operation !== target || version !== previewVersion) return false;
      command.textContent = data.terminal_command || '';
      document.getElementById('operationNote').textContent = data.terminal_note || '';
      copyButton.disabled = !data.terminal_ready;
      runButton.disabled = false;
      operationStatus.textContent = '';
      operationStatus.dataset.tone = '';
      return true;
    } catch (error) {
      if (operation === target && version === previewVersion) {
        command.textContent = '';
        operationStatus.textContent = error.message;
        operationStatus.dataset.tone = 'error';
      }
      return false;
    }
  }
  function placement(button) {
    const entry = button?.closest('[data-triage-entry]');
    return {slot: button?.closest('[data-operation-slot]')?.dataset.operationSlot || (entry ? `entry-${entry.dataset.triageEntry}` : 'tab-result'),
      tab: state().tab, scope: scopeKey(), input: inputKey(), returnFocus: focusSelector(button)};
  }
  function revealOperation() {
    // Reveal only the start of a newly requested examination, moving down if it
    // is below the viewport. Updating or completing a job never calls this.
    const top = panel.getBoundingClientRect().top;
    if (!panel.hidden && top > innerHeight - 120) window.scrollBy({top: top - innerHeight + 180, behavior: 'instant'});
    document.getElementById('operationTitle').focus({preventScroll: true});
  }
  function resetPanel(title) {
    ++previewVersion;
    ++resultVersion;
    clearTimeout(previewTimer);
    document.getElementById('operationTitle').textContent = title;
    result.replaceChildren();
    command.textContent = '';
    copyButton.disabled = true;
    operationStatus.textContent = '';
    operationStatus.dataset.tone = '';
    document.getElementById('operationCli').open = false;
    options.open = false;
    cancelButton.disabled = false;
  }
  async function openAction(button) {
    if (busy || button.disabled) return;
    const row = button.closest('[data-triage-entry]');
    if (row) selectEntry(row.dataset.triageEntry);
    const values = JSON.parse(button.dataset.payload);
    const existing = [...active.values()].find(job => job.input === inputKey() && matchesAction(job, button.dataset.workspaceTool, values, JSON.parse(button.dataset.fields || '[]')));
    if (existing) { await openResult(existing.runId, button); return; }
    operation = {tool: button.dataset.workspaceTool, payload: values,
      label: button.dataset.label, advance: button.dataset.advance === 'true', ...placement(button)};
    resetPanel(operation.label);
    buildFields(JSON.parse(button.dataset.fields || '[]'), operation.payload);
    options.open = operation.tool.startsWith('blk') || operation.slot === 'disk-options' || fields.querySelector('[required]') !== null;
    runButton.hidden = false;
    runButton.disabled = true;
    cancelButton.hidden = true;
    runButton.textContent = `Run ${operation.tool}`;
    operationStatus.textContent = 'Preparing examination…';
    mountOperation();
    revealOperation();
    if (button.dataset.configure === 'true') await preview();
    else {
      busy = true;
      try { if (await preview()) await enqueue(); } finally { busy = false; }
    }
  }
  async function enqueue() {
    if (!operation || operation.runId || runButton.disabled) return;
    const target = operation;
    const submitted = payload();
    runButton.disabled = true;
    try {
      const data = await post(`/api/${target.tool}/run`, submitted);
      target.runId = data.run_id;
      target.payload = submitted;
      active.set(data.run_id, target);
      if (operation === target) {
        runButton.hidden = true;
        options.hidden = true;
        cancelButton.hidden = false;
        fields.querySelectorAll('input,select').forEach(field => { field.disabled = true; });
        operationStatus.textContent = 'Queued. Waiting for the worker…';
        command.textContent = data.terminal_command || command.textContent;
        if (target.tab === state().tab && target.input === inputKey()) {
          const url = new URL(location.href);
          url.searchParams.set('run', data.run_id);
          history.replaceState(null, '', url);
        }
      }
    } catch (error) {
      if (target === operation) {
        operationStatus.textContent = error.message;
        operationStatus.dataset.tone = 'error';
        runButton.disabled = false;
      }
    }
  }
  async function showResult(id, report = '', offset = 0, query = result.querySelector('[name="report_q"]')?.value || '') {
    const target = operation, version = ++resultVersion;
    const url = new URL(location.href);
    if (report) url.searchParams.set('report', report); else url.searchParams.delete('report');
    url.searchParams.set('report_offset', offset);
    url.searchParams.set('report_q', query);
    try {
      const data = await json(endpoint(`/run/${encodeURIComponent(id)}`, url));
      if (target !== operation || version !== resultVersion) return;
      result.innerHTML = data.html;
      command.textContent = data.terminal_command || '';
      document.getElementById('operationNote').textContent = data.terminal_note || '';
      copyButton.disabled = !data.terminal_ready;
    } catch (error) { if (target === operation && version === resultVersion) operationStatus.textContent = error.message; }
  }
  async function openResult(id, button) {
    const job = active.get(id);
    operation = {...(job || {}), runId: id, advance: button?.dataset.advance === 'true' || job?.advance, ...placement(button)};
    if (job) active.set(id, operation);
    resetPanel('Recorded examination');
    fields.replaceChildren();
    options.hidden = true;
    runButton.hidden = true;
    cancelButton.hidden = !job;
    operationStatus.textContent = job ? 'Job in progress…' : '';
    for (let element = button?.parentElement; element && element !== view; element = element.parentElement) {
      if (element.tagName === 'DETAILS') element.open = true;
    }
    mountOperation();
    if (button) revealOperation();
    const url = new URL(location.href); url.searchParams.set('run', id); history.replaceState(null, '', url);
    await showResult(id);
  }
  function selectEntry(id) {
    for (const row of view.querySelectorAll('.triage-detail-row')) row.hidden = row.id !== `entry-${id}`;
    for (const trigger of view.querySelectorAll('[data-inspect-entry]')) trigger.setAttribute('aria-expanded', String(trigger.dataset.inspectEntry === id));
    const url = new URL(location.href); url.searchParams.set('entry', id); url.searchParams.delete('run'); history.replaceState(null, '', url);
  }
  async function inspectEntry(button) {
    if (busy) return;
    const id = button.dataset.inspectEntry;
    selectEntry(id);
    const entry = document.getElementById(`entry-${id}`);
    const metadata = entry.querySelector('[data-entry-metadata-action]');
    if (metadata?.dataset.workspaceResult) await openResult(metadata.dataset.workspaceResult, metadata);
    else if (metadata) await openAction(metadata);
    else { operation = null; mountOperation(); }
  }
  async function poll() {
    if (polling || document.hidden || (!active.size && !needsRefresh)) return;
    polling = true;
    try {
      await Promise.all([...active].map(async ([id, job]) => {
        try {
          const data = await json(`/api/run/${encodeURIComponent(id)}/status`);
          if (job.input !== inputKey()) return;
          if (['queued', 'running'].includes(data.status)) {
            if (operation?.runId === id) operationStatus.textContent = `${data.status === 'queued' ? 'Queued' : 'Running'}${data.current_step ? ` · ${data.current_step}` : '…'}`;
            return;
          }
          active.delete(id);
          needsRefresh = true;
          if (operation?.runId === id) {
            cancelButton.hidden = true;
            operationStatus.textContent = data.status === 'success' ? 'Completed.' : `${data.status}: ${data.error || 'The job did not complete.'}`;
            operationStatus.dataset.tone = data.status === 'success' ? 'success' : 'error';
            if (data.status === 'success' && (job.advance || ['mmls', 'fsstat', 'icat'].includes(job.tool) || (job.tool === 'fls' && !job.payload?.entry_id))) {
              operation.dismissed = true;
              const url = new URL(location.href); url.searchParams.delete('run'); history.replaceState(null, '', url);
            } else await showResult(id);
          }
        } catch (error) { announce(`Job updates unavailable: ${error.message} Retrying automatically.`, true); }
      }));
      if (needsRefresh && !view.hasAttribute('aria-busy')) needsRefresh = !(await render(new URL(location.href), '', {background: true}));
    } finally { polling = false; }
  }
  root.addEventListener('click', event => {
    const button = event.target.closest('button,a');
    if (!button) return;
    if (button.dataset.workspaceTab) { event.preventDefault(); void tab(button.dataset.workspaceTab, {}, button.getAttribute('role') === 'tab'); }
    else if (button.matches('[data-workspace-link]')) {
      const url = new URL(button.href);
      if (url.pathname !== location.pathname || url.origin !== location.origin || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      event.preventDefault(); void navigate(url);
    } else if (button.dataset.retireEvidence) {
      if (!confirm('Retire this evidence? Files and custody records will be retained.')) return;
      button.disabled = true;
      void json(`/api/case/${caseId}/artifacts/${button.dataset.retireEvidence}`, {method: 'DELETE'})
        .then(() => { location.href = `/case/${caseId}/workspace`; })
        .catch(error => { announce(error.message, true); button.disabled = false; });
    } else if (button.dataset.verifyEvidence) {
      button.disabled = true;
      void (async () => {
        try {
          const response = await fetch(`/api/case/${caseId}/evidence/${button.dataset.verifyEvidence}/verify`, {method: 'POST'});
          const data = await response.json();
          if (!response.ok) throw new Error(data.error);
          await render();
        } catch (error) { announce(error.message, true); button.disabled = false; }
      })();
    } else if (button.hasAttribute('data-report-offset')) { void showResult(button.dataset.run, button.dataset.report, Number(button.dataset.reportOffset)); }
    else if (button.hasAttribute('data-process-row') || button.hasAttribute('data-close-process') || button.hasAttribute('data-process-page')) {
      const url = new URL(location.href);
      url.searchParams.set('inventory_run_id', state().inventory);
      url.searchParams.set('memory_os', state().memory_os);
      url.searchParams.delete('process_row');
      if (button.dataset.processRow) url.searchParams.set('process_row', button.dataset.processRow);
      if (button.hasAttribute('data-process-page')) url.searchParams.set('process_offset', button.dataset.processPage);
      void navigate(url, button.hasAttribute('data-close-process') ? {focus: at('data-process-row', button.dataset.closeProcess)} : {});
    } else if (button.dataset.inspectEntry) { void inspectEntry(button); }
    else if (button.dataset.closeEntry) {
      document.getElementById(`entry-${button.dataset.closeEntry}`).hidden = true;
      const trigger = view.querySelector(at('data-inspect-entry', button.dataset.closeEntry));
      trigger.setAttribute('aria-expanded', 'false'); trigger.focus({preventScroll: true});
      if (operation?.slot === `entry-${button.dataset.closeEntry}`) { operation.dismissed = true; mountOperation(); }
      const url = new URL(location.href); url.searchParams.delete('entry'); url.searchParams.delete('run'); history.replaceState(null, '', url);
    } else if (button.dataset.workspaceTool) { void openAction(button); }
    else if (button.dataset.examine) {
      if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      event.preventDefault(); void tab('derived', {examine: button.dataset.examine}, '#derivedExamination');
    }
    else if (button.matches('[data-close-examination]')) { void tab('derived', {examine: null}, at('data-examine', state().examine)); }
    else if (button.dataset.workspaceResult) { void openResult(button.dataset.workspaceResult, button); }
  });
  root.addEventListener('keydown', event => {
    const button = event.target.closest('[role="tab"]');
    if (!button || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const buttons = [...view.querySelectorAll('[role="tab"]')], index = buttons.indexOf(button);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
    void tab(buttons[next].dataset.workspaceTab, {}, true);
  });
  root.addEventListener('change', event => {
    if (event.target.id === 'triageFilesystem') {
      const url = new URL(location.href);
      for (const key of ['directory', 'q', 'kind', 'state', 'scope', 'offset', 'entry', 'run']) url.searchParams.delete(key);
      if (event.target.value) url.searchParams.set('context_run_id', event.target.value); else url.searchParams.delete('context_run_id');
      void navigate(url);
    } else if (event.target.matches('#triageFilters select, #memoryFilters select, #memoryContextForm select, #memoryQuestionForm select')) event.target.form.requestSubmit();
    else if (event.target.id === 'operationReport') void showResult(event.target.dataset.run, event.target.value, 0, '');
  });
  fields.addEventListener('input', () => {
    ++previewVersion;
    runButton.disabled = true;
    copyButton.disabled = true;
    clearTimeout(previewTimer);
    previewTimer = setTimeout(() => { void preview(); }, 250);
  });
  root.addEventListener('submit', event => {
    if (event.target.id === 'workspaceReportSearch') {
      event.preventDefault();
      void showResult(event.target.dataset.run, event.target.dataset.report, 0, new FormData(event.target).get('report_q'));
    } else if (event.target.id === 'memoryQuestionForm') {
      event.preventDefault();
      const url = new URL(location.href);
      url.searchParams.set('memory_os', state().memory_os);
      url.searchParams.set('memory_question', new FormData(event.target).get('memory_question'));
      void navigate(url);
    } else if (event.target.id === 'triageFilters') {
      event.preventDefault();
      const url = new URL(location.href);
      for (const key of ['directory', 'q', 'kind', 'state', 'scope', 'offset', 'entry', 'run']) url.searchParams.delete(key);
      for (const [key, value] of new FormData(event.target)) url.searchParams.set(key, value);
      void navigate(url);
    } else if (event.target.id === 'memoryContextForm' || event.target.id === 'memoryFilters') {
      event.preventDefault();
      const url = new URL(location.href);
      for (const name of ['process_q', 'process_offset', 'process_row', 'inventory_run_id', 'run']) url.searchParams.delete(name);
      if (event.target.id === 'memoryFilters') {
        url.searchParams.set('memory_os', state().memory_os);
        url.searchParams.set('inventory_run_id', state().inventory);
      }
      for (const [key, value] of new FormData(event.target)) if (value) url.searchParams.set(key, value);
      void navigate(url);
    } else if (event.target.id === 'operationForm') {
      event.preventDefault();
      if (!busy && !runButton.disabled) { busy = true; void enqueue().finally(() => { busy = false; }); }
    } else if (event.target.id === 'evidenceTypeForm') {
      event.preventDefault();
      const form = event.target;
      void (async () => {
        try {
          const response = await fetch(form.action, {method: 'POST', body: new FormData(form)});
          if (!response.ok) throw new Error('The evidence type could not be saved.');
          await render();
        } catch (error) { announce(error.message, true); }
      })();
    }
  });
  document.getElementById('closeOperation').addEventListener('click', () => {
    if (operation) operation.dismissed = true;
    mountOperation(); ++previewVersion;
    view.querySelector(operation?.returnFocus || '#workspaceTabPanel')?.focus({preventScroll: true});
    const url = new URL(location.href); url.searchParams.delete('run'); history.replaceState(null, '', url);
  });
  cancelButton.addEventListener('click', async () => {
    if (!operation?.runId) return;
    const target = operation;
    cancelButton.disabled = true;
    try { const data = await post(`/api/run/${target.runId}/cancel`, {}); if (target === operation) operationStatus.textContent = data.message; }
    catch (error) { if (target === operation) { operationStatus.textContent = error.message; cancelButton.disabled = false; } }
  });
  copyButton.addEventListener('click', async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(command.textContent);
      else {
        const textarea = document.createElement('textarea'); textarea.value = command.textContent;
        textarea.style.position = 'fixed'; textarea.style.opacity = '0';
        document.body.append(textarea); textarea.select();
        const copied = document.execCommand('copy'); textarea.remove(); copyButton.focus({preventScroll: true});
        if (!copied) throw new Error('Select the command and copy it manually.');
      }
      operationStatus.textContent = 'Command copied.';
    } catch (error) { operationStatus.textContent = error.message; }
  });
  window.addEventListener('popstate', () => { void render(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void poll(); });
  loadTabs(); saveTab(); seedActive(state().active); revealActiveTab();
  const recordedRun = new URL(location.href).searchParams.get('run');
  if (recordedRun) {
    const job = active.get(recordedRun), params = job?.payload || {};
    const source = view.querySelector(at('data-workspace-result', recordedRun))
      || [...view.querySelectorAll('[data-workspace-tool]')].find(button => job && matchesAction(job, button.dataset.workspaceTool, JSON.parse(button.dataset.payload), JSON.parse(button.dataset.fields || '[]')))
      || view.querySelector('.triage-detail-row:not([hidden]) [data-entry-metadata-action]')
      || (job?.tool === 'mmls' ? view.querySelector('[data-operation-slot="disk-map"] button, [data-operation-slot="disk-options"] button') : null)
      || view.querySelector(`${at('data-operation-slot', `filesystem-${params.offset_sector}-${params.sector_size || 'auto'}`)} [data-workspace-tool]`)
      || (job ? view.querySelector(`${at('data-evidence-action', params.parser_id || job.tool)} button`) : null);
    void openResult(recordedRun, source);
  }
  setInterval(poll, 1250);
})();
