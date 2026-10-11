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
  const runButton = document.getElementById('runOperation');
  const cancelButton = document.getElementById('cancelOperation');
  const copyButton = document.getElementById('copyOperation');
  const command = document.getElementById('operationCommand');
  const result = document.getElementById('operationResult');
  const active = new Map();
  let operation = null, busy = false, rendering = 0, previewVersion = 0, polling = false, previewTimer;
  const state = () => JSON.parse(document.getElementById('workspaceState').textContent);
  const inputKey = () => state().input;
  const savedKey = () => `sifted-workspace:${caseId}:${inputKey()}`;
  function mountOperation() {
    const content = view.querySelector('.workspace-tab-content');
    if (content) content.before(panel);
  }
  let tabs = {};
  function loadTabs() {
    try { tabs = JSON.parse(sessionStorage.getItem(savedKey()) || '{}'); } catch (_) { tabs = {}; }
  }
  function saveTab() {
    tabs[state().tab] = location.search;
    try { sessionStorage.setItem(savedKey(), JSON.stringify(tabs)); } catch (_) { /* Storage may be disabled. */ }
  }
  function announce(message, error = false) {
    status.textContent = message;
    status.dataset.tone = error ? 'error' : '';
  }
  async function json(url, options) {
    const response = await fetch(url, options);
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
  async function render(url = new URL(location.href), historyMode = '') {
    const version = ++rendering;
    announce('Updating workspace…');
    try {
      const data = await json(endpoint('/view', url));
      if (version !== rendering) return;
      if (historyMode === 'push') history.pushState(null, '', url);
      if (historyMode === 'replace') history.replaceState(null, '', url);
      const previousInput = inputKey();
      // Keep the live examination intact when the server refreshes the tab content.
      root.append(panel);
      view.innerHTML = data.html;
      mountOperation();
      if (inputKey() !== previousInput) {
        panel.hidden = true;
        operation = null;
        ++previewVersion;
        active.clear();
        loadTabs();
      }
      seedActive(data.active);
      saveTab();
      announce('');
    } catch (error) { if (version === rendering) announce(error.message, true); }
  }
  async function navigate(url) {
    saveTab();
    await render(url, 'push');
  }
  async function tab(name, changes = {}) {
    saveTab();
    const url = new URL(location.href);
    if (tabs[name]) {
      const saved = new URLSearchParams(tabs[name]);
      // Preserve the directory and filters for each tab; keep the root evidence stable.
      for (const key of ['context_run_id', 'directory', 'q', 'kind', 'state', 'scope', 'offset', 'examine']) {
        url.searchParams.delete(key);
        if (saved.has(key)) url.searchParams.set(key, saved.get(key));
      }
    }
    url.searchParams.set('tab', name);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) url.searchParams.delete(key); else url.searchParams.set(key, value);
    }
    await render(url, 'push');
  }
  function payload() {
    const data = {...operation.payload};
    for (const field of fields.querySelectorAll('[data-field]')) {
      if (field.type === 'checkbox') data[field.dataset.field] = field.checked;
      else if (field.value !== '') data[field.dataset.field] = field.dataset.valueType === 'number' ? Number(field.value) : field.value;
      else delete data[field.dataset.field];
    }
    return data;
  }
  function buildFields(specs, values) {
    fields.replaceChildren();
    for (const spec of specs) {
      const label = document.createElement('label');
      label.append(document.createTextNode(spec.label));
      const field = document.createElement(spec.type === 'select' ? 'select' : 'input');
      field.dataset.field = spec.name;
      field.dataset.valueType = spec.type === 'number' || (spec.type === 'select' && spec.choices.some(([value]) => typeof value === 'number')) ? 'number' : 'text';
      if (spec.type === 'select') {
        for (const [value, text] of spec.choices) field.add(new Option(text, value));
      } else field.type = spec.type;
      if (spec.min !== undefined) field.min = spec.min;
      if (spec.max !== undefined) field.max = spec.max;
      if (spec.placeholder) field.placeholder = spec.placeholder;
      const value = values[spec.name] ?? spec.default;
      if (spec.type === 'checkbox') field.checked = Boolean(value); else field.value = value ?? '';
      label.append(field);
      fields.append(label);
    }
  }
  async function preview() {
    if (!operation || operation.runId) return false;
    const version = ++previewVersion;
    const target = operation;
    runButton.disabled = true;
    copyButton.disabled = true;
    try {
      const data = await post(`/api/${target.tool}/preview`, payload());
      if (operation !== target || version !== previewVersion) return false;
      command.textContent = data.terminal_command || '';
      document.getElementById('operationNote').textContent = data.terminal_note || '';
      copyButton.disabled = !data.terminal_ready;
      runButton.disabled = false;
      operationStatus.textContent = '';
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
  async function openAction(button) {
    if (busy) return;
    operation = {tool: button.dataset.workspaceTool, payload: JSON.parse(button.dataset.payload),
                 next: button.dataset.next, input: inputKey(), label: button.dataset.label};
    panel.hidden = false;
    const entry = button.closest('[data-entry-label]');
    document.getElementById('operationTitle').textContent = entry ? `${operation.label} · ${entry.dataset.entryLabel}` : operation.label;
    buildFields(JSON.parse(button.dataset.fields || '[]'), operation.payload);
    result.replaceChildren();
    operationStatus.textContent = 'Preparing examination…';
    command.textContent = '';
    runButton.hidden = false;
    cancelButton.hidden = true;
    operationStatus.dataset.tone = '';
    document.getElementById('operationCli').open = button.dataset.configure === 'true';
    runButton.textContent = `Run ${operation.tool}`;
    if (button.dataset.configure === 'true') {
      panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
      await preview();
    } else {
      busy = true;
      try { if (await preview()) await enqueue(); } finally { busy = false; }
    }
  }
  async function enqueue() {
    if (!operation || operation.runId) return;
    const target = operation;
    runButton.disabled = true;
    try {
      const data = await post(`/api/${target.tool}/run`, payload());
      target.runId = data.run_id;
      active.set(data.run_id, target);
      if (operation === target) {
        runButton.hidden = true;
        cancelButton.hidden = false;
        cancelButton.disabled = false;
        fields.querySelectorAll('input,select').forEach(field => { field.disabled = true; });
        operationStatus.textContent = 'Queued. Waiting for the worker…';
        panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
        command.textContent = data.terminal_command || command.textContent;
        const url = new URL(location.href);
        url.searchParams.set('run', data.run_id);
        history.replaceState(null, '', url);
      }
    } catch (error) {
      operationStatus.textContent = error.message;
      operationStatus.dataset.tone = 'error';
      runButton.disabled = false;
    }
  }
  async function showResult(id, report = '', scroll = true) {
    const target = operation;
    const url = new URL(location.href);
    if (report) url.searchParams.set('report', report); else url.searchParams.delete('report');
    try {
      const data = await json(endpoint(`/run/${encodeURIComponent(id)}`, url));
      if (target !== operation) return;
      result.innerHTML = data.html;
      if (operation?.runId === id) {
        command.textContent = data.terminal_command || '';
        document.getElementById('operationNote').textContent = data.terminal_note || '';
        copyButton.disabled = !data.terminal_ready;
      }
      if (scroll) panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    } catch (error) { if (target === operation) operationStatus.textContent = error.message; }
  }
  async function openResult(id) {
    operation = active.get(id) || {runId: id, input: inputKey()};
    panel.hidden = false;
    document.getElementById('operationTitle').textContent = 'Recorded examination';
    fields.replaceChildren();
    command.textContent = '';
    copyButton.disabled = true;
    runButton.hidden = true;
    cancelButton.hidden = !active.has(id);
    operationStatus.textContent = active.has(id) ? 'Job in progress…' : '';
    result.replaceChildren();
    await showResult(id);
  }
  async function poll() {
    if (polling || document.hidden || !active.size) return;
    polling = true;
    let changed = false, next = null, completedPreparation = false;
    try {
      await Promise.all([...active].map(async ([id, job]) => {
        try {
          const data = await json(`/api/run/${encodeURIComponent(id)}/status`);
          if (['queued', 'running'].includes(data.status)) {
            if (operation?.runId === id) operationStatus.textContent = `${data.status === 'queued' ? 'Queued' : 'Running'}${data.current_step ? ` · ${data.current_step}` : '…'}`;
            return;
          }
          active.delete(id);
          if (job.input !== inputKey()) return;
          changed = true;
          if (operation?.runId === id) {
            cancelButton.hidden = true;
            operationStatus.textContent = data.status === 'success' ? 'Completed.' : `${data.status}: ${data.error || 'The job did not complete.'}`;
            operationStatus.dataset.tone = data.status === 'success' ? 'success' : 'error';
            if (data.status === 'success' && job.next) next = {tab: job.next, id, tool: job.tool};
            completedPreparation = data.status === 'success' && (Boolean(job.next) || ['mmls', 'fsstat'].includes(job.tool));
            await showResult(id, '', false);
          }
        } catch (error) { announce(`Job updates unavailable: ${error.message} Retrying automatically.`, true); }
      }));
      if (next) {
        const changes = next.tool === 'fls' ? {context_run_id: next.id, directory: null, offset: null, q: null, state: null, kind: null, scope: null} : {};
        await tab(next.tab, changes);
      } else if (changed) await render();
      if (completedPreparation) panel.hidden = true;
    } finally { polling = false; }
  }
  root.addEventListener('click', event => {
    const button = event.target.closest('button,a');
    if (!button) return;
    if (button.dataset.workspaceTab) { event.preventDefault(); void tab(button.dataset.workspaceTab); }
    else if (button.matches('[data-workspace-link]')) {
      const url = new URL(button.href);
      if (url.pathname !== location.pathname || url.origin !== location.origin || event.ctrlKey || event.metaKey) return;
      event.preventDefault(); void navigate(url);
    } else if (button.dataset.workspaceTool) { void openAction(button); }
    else if (button.dataset.examine) { void tab('derived', {examine: button.dataset.examine}); }
    else if (button.matches('[data-close-examination]')) { void tab('derived', {examine: null}); }
    else if (button.dataset.workspaceResult) { void openResult(button.dataset.workspaceResult); }
  });
  root.addEventListener('change', event => {
    if (event.target.id === 'workspaceInput') {
      const url = new URL(location.pathname, location.origin);
      url.searchParams.set('input', event.target.value);
      void navigate(url);
    } else if (event.target.id === 'triageFilesystem') {
      const url = new URL(location.href);
      for (const key of ['directory', 'q', 'kind', 'state', 'scope', 'offset']) url.searchParams.delete(key);
      if (event.target.value) url.searchParams.set('context_run_id', event.target.value);
      else url.searchParams.delete('context_run_id');
      void navigate(url);
    } else if (event.target.id === 'operationReport') void showResult(event.target.dataset.run, event.target.value, false);
  });
  fields.addEventListener('input', () => {
    ++previewVersion;
    runButton.disabled = true;
    copyButton.disabled = true;
    clearTimeout(previewTimer);
    previewTimer = setTimeout(() => { void preview(); }, 250);
  });
  root.addEventListener('submit', event => {
    if (event.target.id === 'triageFilters') {
      event.preventDefault();
      const url = new URL(location.href);
      for (const key of ['directory', 'q', 'kind', 'state', 'scope', 'offset']) url.searchParams.delete(key);
      for (const [key, value] of new FormData(event.target)) url.searchParams.set(key, value);
      void navigate(url);
    } else if (event.target.id === 'operationForm') {
      event.preventDefault();
      if (!busy) { busy = true; void enqueue().finally(() => { busy = false; }); }
    }
  });
  document.getElementById('closeOperation').addEventListener('click', () => {
    panel.hidden = true; operation = null; ++previewVersion;
    const url = new URL(location.href); url.searchParams.delete('run'); history.replaceState(null, '', url);
  });
  cancelButton.addEventListener('click', async () => {
    if (!operation?.runId) return;
    cancelButton.disabled = true;
    try { const data = await post(`/api/run/${operation.runId}/cancel`, {}); operationStatus.textContent = data.message; }
    catch (error) { operationStatus.textContent = error.message; cancelButton.disabled = false; }
  });
  copyButton.addEventListener('click', async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(command.textContent);
      else {
        const textarea = document.createElement('textarea'); textarea.value = command.textContent;
        document.body.append(textarea); textarea.select();
        const copied = document.execCommand('copy'); textarea.remove();
        if (!copied) throw new Error('Select the command and copy it manually.');
      }
      operationStatus.textContent = 'Command copied.';
    } catch (error) { operationStatus.textContent = error.message; }
  });
  window.addEventListener('popstate', () => { void render(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void poll(); });
  mountOperation(); loadTabs(); saveTab(); seedActive(state().active);
  const recordedRun = new URL(location.href).searchParams.get('run');
  if (recordedRun) void openResult(recordedRun);
  setInterval(poll, 1250);
})();
