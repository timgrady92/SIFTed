const runGroups = Array.from(document.querySelectorAll(".run-group"));
runGroups.forEach((group) => {
  const toggle = group.querySelector(".run-group-toggle");
  const body = group.querySelector(".run-group-body");
  const label = group.querySelector(".run-group-label");
  if (!toggle || !body) {
    return;
  }
  toggle.addEventListener("click", () => {
    const isOpen = group.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(isOpen));
    if (label) {
      const next = isOpen ? label.dataset.openLabel : label.dataset.closedLabel;
      if (next) {
        label.textContent = next;
      }
    }
  });
});

const runResults = Array.from(document.querySelectorAll(".run-results"));
runResults.forEach((block) => {
  const toggle = block.querySelector(".run-results-toggle");
  const body = block.querySelector(".run-results-body");
  const label = block.querySelector(".run-results-label");
  if (!toggle || !body) {
    return;
  }
  toggle.addEventListener("click", () => {
    const isOpen = block.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(isOpen));
    if (label) {
      const next = isOpen ? label.dataset.openLabel : label.dataset.closedLabel;
      if (next) {
        label.textContent = next;
      }
    }
  });
});


(() => {
  const byId = id => document.getElementById(id);
  const modal = byId('addArtifactModal'), form = byId('addArtifactForm');
  const status = byId('intakeStatus'), progress = byId('intakeProgress');
  const drawer = byId('browserDrawer');
  let currentPath = '', busy = false, opener;
  const stored = key => { try { return localStorage.getItem(key); } catch { return null; } };
  const store = (key, value) => { try { if (value) localStorage.setItem(key, value); else localStorage.removeItem(key); } catch { /* Transfers still work without browser storage. */ } };
  const json = async (url, options = {}) => {
    const response = await fetch(url, options);
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || `Request failed (${response.status})`);
    return value;
  };
  const post = (url, data) => json(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
  const methodChanged = () => {
    const upload = byId('intakeMethod').value === 'upload';
    byId('intakePathField').hidden = upload;
    byId('intakeUploadFields').hidden = !upload;
    byId('artifactPath').required = !upload;
    byId('evidenceFiles').required = upload;
  };
  byId('intakeMethod').addEventListener('change', methodChanged);
  byId('evidenceFiles').addEventListener('change', () => {
    const files = [...byId('evidenceFiles').files], select = byId('intakePrimary');
    select.replaceChildren(new Option('Collected directory', ''));
    files.forEach((file, index) => select.add(new Option(`Primary file: ${file.name}`, String(index))));
    select.value = files.length === 1 ? '0' : '';
    byId('intakePrimaryField').hidden = files.length <= 1;
  });
  const close = () => {
    if (busy) return;
    modal.classList.remove('open'); modal.setAttribute('aria-hidden', 'true'); opener?.focus();
  };
  byId('closeArtifactModal').addEventListener('click', close);
  modal.addEventListener('keydown', event => {
    if (event.key === 'Escape') close();
    if (event.key !== 'Tab') return;
    const controls = [...modal.querySelectorAll('button,input,select,textarea,summary')].filter(e => !e.disabled && e.getClientRects().length);
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });
  document.addEventListener('click', async event => {
    const add = event.target.closest('.add-artifact-btn');
    if (add) {
      opener = add; form.reset(); byId('artifactCaseId').value = add.dataset.caseId;
      status.textContent = ''; progress.hidden = true; methodChanged();
      modal.classList.add('open'); modal.setAttribute('aria-hidden', 'false'); byId('intakeMethod').focus();
    }
    const remove = event.target.closest('.artifact-remove');
    if (remove && confirm('Retire this evidence from active casework? Its files and custody record will be retained.')) {
      try {
        await json(`/api/case/${remove.closest('.case-artifacts').dataset.caseId}/artifacts/${remove.dataset.artifactId}`, {method: 'DELETE'});
        location.reload();
      } catch (error) { alert(error.message); }
    }
  });
  const toggleDrawer = open => { drawer.classList.toggle('open', open); drawer.setAttribute('aria-hidden', String(!open)); };
  const choose = path => { byId('artifactPath').value = path; toggleDrawer(false); byId('artifactPath').focus(); };
  const browse = async path => {
    try {
      const data = await json(`/api/browse?path=${encodeURIComponent(path)}`);
      currentPath = data.path; byId('currentPath').textContent = currentPath;
      const list = byId('drawerList'); list.replaceChildren(); byId('drawerError').hidden = true;
      const folder = document.createElement('button'); folder.type = 'button'; folder.className = 'drawer-item'; folder.textContent = 'Use this directory'; folder.addEventListener('click', () => choose(currentPath)); list.append(folder);
      for (const entry of [...(data.parent ? [{path: data.parent, name: '..', type: 'dir'}] : []), ...data.entries]) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'drawer-item'; button.textContent = entry.name;
        button.addEventListener('click', () => entry.type === 'dir' ? browse(entry.path) : choose(entry.path)); list.append(button);
      }
    } catch (error) { byId('drawerError').textContent = error.message; byId('drawerError').hidden = false; }
  };
  byId('browseArtifact').addEventListener('click', () => { toggleDrawer(true); browse(currentPath); });
  byId('closeBrowser').addEventListener('click', () => toggleDrawer(false));
  byId('useManualPath').addEventListener('click', () => choose(byId('manualPath').value.trim()));
  document.querySelectorAll('.path-chip').forEach(chip => chip.addEventListener('click', () => browse(chip.dataset.path)));
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    const caseId = byId('artifactCaseId').value;
    const info = {custodian: byId('intakeCustodian').value, label: byId('artifactLabel').value,
      source: byId('intakeSource').value, notes: byId('intakeNotes').value, expected_sha256: byId('intakeHash').value};
    busy = true;
    const controls = [...form.querySelectorAll('input,select,textarea,button'), byId('closeArtifactModal')];
    controls.forEach(control => control.disabled = true);
    try {
      let result;
      if (byId('intakeMethod').value === 'path') {
        status.textContent = 'Queueing evidence verification…';
        result = await post(`/api/case/${caseId}/artifacts`, {path: byId('artifactPath').value, ...info});
      } else {
        const files = [...byId('evidenceFiles').files];
        const primary = byId('intakePrimary').value === '' ? null : Number(byId('intakePrimary').value);
        const spec = {files: files.map(file => ({name: file.name, size: file.size})), primary, metadata: info};
        const storageKey = `sifted-upload:${caseId}:${JSON.stringify(spec)}`;
        let session;
        const saved = stored(storageKey);
        if (saved) {
          try { session = await json(`/api/case/${caseId}/uploads/${saved}`); } catch { store(storageKey, null); }
        }
        if (!session || session.status === 'discarded') {
          session = await post(`/api/case/${caseId}/uploads`, spec); store(storageKey, session.id);
        }
        const base = `/api/case/${caseId}/uploads/${session.id}`;
        progress.hidden = false;
        if (session.status === 'uploading') {
          let sent = 0;
          const total = files.reduce((n, file) => n + file.size, 0);
          for (const [index, file] of files.entries()) {
            // Replaying the prefix checks that a reselected file matches every
            // byte already received; name and size alone never establish identity.
            for (let offset = 0; offset < file.size; offset += session.chunk_bytes) {
              const chunk = file.slice(offset, offset + session.chunk_bytes);
              status.textContent = `Transferring ${file.name} · ${Math.floor(100 * sent / Math.max(total, 1))}%`;
              await json(`${base}/${index}`, {method: 'PUT', headers: {'Upload-Offset': String(offset), 'Content-Type': 'application/octet-stream'}, body: chunk});
              sent += chunk.size; progress.value = 100 * sent / Math.max(total, 1);
            }
          }
        }
        status.textContent = 'Transfer complete. Queueing verification…';
        result = await post(`${base}/complete`, {}); store(storageKey, null);
      }
      location.href = `/case/${caseId}/workspace?input=e:${result.artifact.id}&tab=overview`;
    } catch (error) {
      status.textContent = `${error.message} You can retry; interrupted transfers resume with their received bytes checked.`;
    } finally { busy = false; controls.forEach(control => control.disabled = false); }
  });
})();
