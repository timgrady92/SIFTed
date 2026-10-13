/* The same live catalog and rendered content feed pages, sidebars, previews and tooltips. */
(() => {
  'use strict';
  const bootstrap = document.getElementById('referenceCatalog');
  if (!bootstrap) return;
  let catalog = JSON.parse(bootstrap.textContent);
  let byId = new Map();
  const renderers = [];
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const all = (selector, root = document) => [...root.querySelectorAll(selector)];
  const label = entry => catalog.categories[entry.kind === 'guide' ? 'guides' : entry.section][entry.category] || entry.category;
  const matches = (entry, query) => !query || `${entry.title} ${JSON.stringify(entry.data)} ${label(entry)}`.toLowerCase().includes(query.toLowerCase().trim());
  const management = entry => `<div class="reference-management"><a class="ghost" href="/reference/${encodeURIComponent(entry.id)}/edit">Edit${entry.origin === 'builtin' ? ' local copy' : ''}</a><a class="ghost" href="/reference/new?copy=${encodeURIComponent(entry.id)}">Use as template</a></div>`;
  const detail = entry => entry.html + management(entry);
  function reindex() { byId = new Map(catalog.records.map(entry => [entry.id, entry])); }
  reindex();

  let pendingRefresh;
  async function refresh(notify = false) {
    if (!pendingRefresh) pendingRefresh = (async () => {
      const response = await fetch('/api/reference', {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to refresh reference content.');
      catalog = await response.json();
      reindex();
      renderers.forEach(render => render());
      document.dispatchEvent(new CustomEvent('sifted:reference-changed'));
    })().finally(() => { pendingRefresh = null; });
    await pendingRefresh;
    if (notify) localStorage.setItem('sifted.reference.changed', `${Date.now()}-${Math.random()}`);
    return catalog;
  }
  window.SiftedReference = {get catalog() { return catalog; }, get: id => byId.get(id), refresh, escape, management};
  window.addEventListener('focus', () => refresh().catch(() => {}));
  window.addEventListener('storage', event => {
    if (event.key === 'sifted.reference.changed') refresh().catch(() => {});
  });

  const glossaryControllers = [];
  all('[data-glossary-surface]').forEach(surface => {
    const sidebar = surface.dataset.glossarySurface === 'sidebar';
    const search = surface.querySelector('[data-glossary-search]');
    const list = surface.querySelector(sidebar ? '[data-sidebar-ref-content]' : '.ref-content');
    const content = surface.querySelector('[data-glossary-detail-content]');
    const pane = surface.querySelector('[data-glossary-detail]');
    const sidebarContent = surface.querySelector('[data-sidebar-content]');
    if (!list || !content) return;
    surface.querySelector('[data-glossary-grid]')?.setAttribute('hidden', '');
    list.style.display = sidebar ? 'flex' : 'block';
    const preference = (key, allowed, fallback) => {
      const value = sidebar ? null : localStorage.getItem(`sifted.glossary.${key}`);
      return allowed.includes(value) ? value : fallback;
    };
    let section = preference('section', ['artifacts','registry','persistence','events'], 'artifacts');
    let mode = preference('viewMode', ['categorized','alphabetical'], 'categorized');
    let os = preference('osFilter', ['all','windows','macos','linux','cross'], 'all'), selected = null;
    const remember = () => {
      if (!sidebar) for (const [key, value] of Object.entries({section, viewMode: mode, osFilter: os})) localStorage.setItem(`sifted.glossary.${key}`, value);
    };
    const expanded = new Set();
    const tabs = all(sidebar ? '[data-sidebar-tab]' : '[data-section-tab]', surface);
    const sectionOf = tab => sidebar ? tab.dataset.sidebarTab : tab.dataset.sectionTab;
    const osMatches = entry => os === 'all' || (entry.data.os || [entry.category === 'linux' ? 'linux' : entry.category === 'macos' ? 'macos' : 'windows']).includes(os);
    function show(id) {
      const entry = byId.get(id);
      if (!entry || entry.kind !== 'glossary') return;
      selected = id;
      section = entry.section;
      pane.hidden = false;
      pane.dataset.referenceId = id;
      content.innerHTML = detail(entry);
      if (sidebarContent) sidebarContent.hidden = true;
      tabs.forEach(tab => tab.classList.toggle('active', sectionOf(tab) === section));
      all('[data-reference-entry]', list).forEach(row => row.classList.toggle('active', row.dataset.referenceEntry === selected));
    }
    function render() {
      all('[data-view-mode]', surface).forEach(el => el.classList.toggle('active', el.dataset.viewMode === mode));
      all('[data-glossary-filter-value]', surface).forEach(el => el.classList.toggle('active', el.dataset.glossaryFilterValue === os));
      const query = search?.value || '';
      const records = catalog.records.filter(entry => entry.kind === 'glossary' && osMatches(entry) && matches(entry, query));
      tabs.forEach(tab => {
        const name = sectionOf(tab);
        tab.classList.toggle('active', name === section);
        tab.querySelector('[data-sidebar-count], .section-tab-count').textContent = records.filter(entry => entry.section === name).length;
      });
      const filtered = records.filter(entry => entry.section === section);
      surface.querySelector('[data-glossary-count]')?.replaceChildren(document.createTextNode(`${filtered.length} entries`));
      const row = entry => `<button type="button" class="artifact-row${entry.id === selected ? ' active' : ''}" data-reference-entry="${escape(entry.id)}" data-artifact="${escape(entry.id)}"><span class="artifact-row-icon">${escape(entry.title.slice(0,2).toUpperCase())}</span><span class="artifact-row-name">${escape(entry.title)}</span><span class="artifact-row-hint">${escape(entry.data.takeaway || entry.what)}</span></button>`;
      if (mode === 'alphabetical') {
        list.innerHTML = `<div class="ref-list ref-list-alphabetical artifact-list">${filtered.sort((a,b) => a.title.localeCompare(b.title)).map(row).join('')}</div>`;
      } else {
        const groups = catalog.categories[section];
        list.innerHTML = Object.entries(groups).map(([key, title]) => {
          const items = filtered.filter(entry => entry.category === key);
          return items.length ? `<div class="ref-category${query || expanded.has(key) ? ' expanded' : ''}" data-category="${escape(key)}"><button type="button" class="ref-category-header" data-reference-category="${escape(key)}" aria-expanded="${!!query || expanded.has(key)}"><span class="ref-category-title">${escape(title)}</span><span class="ref-category-count">${items.length}</span></button><div class="ref-list artifact-list">${items.map(row).join('')}</div></div>` : '';
        }).join('');
      }
      if (!filtered.length) list.innerHTML = '<p class="ref-empty">No matching entries.</p>';
      if (selected && byId.has(selected)) show(selected);
      else {
        content.innerHTML = '<div class="detail-placeholder"><p class="detail-placeholder-title">Select an entry</p><p>Open an entry to view its interpretation and evidence locations.</p></div>';
        pane.hidden = sidebar;
        if (sidebarContent) sidebarContent.hidden = false;
      }
    }
    surface.addEventListener('click', event => {
      const row = event.target.closest('[data-reference-entry]');
      if (row) { show(row.dataset.referenceEntry); return; }
      const group = event.target.closest('[data-reference-category]');
      if (group) {
        const key = group.dataset.referenceCategory;
        expanded.has(key) ? expanded.delete(key) : expanded.add(key);
        group.closest('.ref-category').classList.toggle('expanded');
        group.setAttribute('aria-expanded', group.closest('.ref-category').classList.contains('expanded'));
      }
      const tab = event.target.closest('[data-section-tab], [data-sidebar-tab]');
      if (tab) { section = sectionOf(tab); selected = null; remember(); render(); }
      const view = event.target.closest('[data-view-mode]');
      if (view) { mode = view.dataset.viewMode; remember(); render(); }
      const filter = event.target.closest('[data-glossary-filter-value]');
      if (filter) { os = filter.dataset.glossaryFilterValue; selected = null; remember(); render(); }
      if (event.target.closest('[data-glossary-back]')) { selected = null; render(); }
    });
    search?.addEventListener('input', () => { selected = null; render(); });
    if (!sidebar) document.addEventListener('keydown', event => {
      if (event.altKey || event.ctrlKey || event.metaKey || event.target.closest('input, textarea, select, [contenteditable="true"], [role="dialog"], dialog')) return;
      if (document.querySelector('.glossary-sidebar.open, .guides-sidebar.open')) return;
      const tab = tabs[Number(event.key) - 1];
      if (tab && /^[1-4]$/.test(event.key)) { event.preventDefault(); tab.click(); }
    });
    glossaryControllers.push({sidebar, surface, show});
    renderers.push(render);
    render();
  });

  function sidebarState(kind, open) {
    const surface = document.querySelector(`[data-${kind}-surface="sidebar"]`);
    if (!surface) return;
    surface.classList.toggle('open', open);
    surface.inert = !open;
    surface.setAttribute('aria-hidden', !open);
    document.body.classList.toggle(`${kind}-open`, open);
  }
  document.addEventListener('click', event => {
    for (const kind of ['glossary', 'guides']) {
      if (event.target.closest(`[data-${kind}-toggle]`)) sidebarState(kind, true);
      if (event.target.closest(`[data-${kind}-close]`)) sidebarState(kind, false);
    }
  });
  all('[data-glossary-surface="sidebar"], [data-guides-surface="sidebar"]').forEach(surface => { surface.inert = true; });

  let activeGuide = null, lastGuideButton = null;
  const modal = document.getElementById('guideModal');
  function openGuide(id, button) {
    const entry = byId.get(id);
    if (!entry || !modal) return;
    activeGuide = id;
    lastGuideButton = button || lastGuideButton;
    document.getElementById('guideModalTitle').textContent = entry.title;
    document.getElementById('guideModalSummary').textContent = entry.data.description;
    const category = document.getElementById('guideModalCategory');
    category.textContent = label(entry);
    category.dataset.category = entry.category;
    document.getElementById('guideModalBody').innerHTML = detail(entry);
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    document.getElementById('guideModalClose').focus();
  }
  function closeGuide() {
    activeGuide = null;
    modal?.classList.remove('open');
    modal?.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    lastGuideButton?.focus();
  }
  if (modal) {
    let tab = 'hypothesis';
    const search = document.getElementById('guideSearch');
    const tabs = all('[data-tab][role="tab"]');
    function render() {
      const query = search.value;
      const guides = catalog.records.filter(entry => entry.kind === 'guide');
      const filtered = guides.filter(entry => matches(entry, query));
      all('[data-tab-panel]').forEach(panel => {
        const section = panel.dataset.tabPanel;
        panel.hidden = section !== tab;
        panel.innerHTML = filtered.filter(entry => entry.section === section).map(entry => `<article class="guide-card" data-category="${escape(entry.category)}"><button class="guide-toggle" type="button" data-reference-guide="${escape(entry.id)}" aria-haspopup="dialog"><div class="guide-toggle-content"><span class="guide-icon" data-category="${escape(entry.category)}"></span><div><span class="guide-pill" data-category="${escape(entry.category)}">${escape(label(entry))}</span><h2>${escape(entry.title)}</h2><p class="helper">${escape(entry.data.description)}</p></div></div><span class="guide-toggle-cta">Open guide →</span></button></article>`).join('');
      });
      const count = filtered.filter(entry => entry.section === tab).length;
      document.getElementById('guideCount').textContent = `${count} of ${guides.filter(entry => entry.section === tab).length} guides`;
      document.getElementById('guideEmpty').hidden = count > 0;
      document.getElementById('clearGuideSearch').hidden = !query;
      if (activeGuide) openGuide(activeGuide);
    }
    search.addEventListener('input', render);
    tabs.forEach(button => button.addEventListener('click', () => {
      tab = button.dataset.tab;
      tabs.forEach(other => { other.classList.toggle('active', other === button); other.setAttribute('aria-selected', other === button); });
      render();
    }));
    document.getElementById('clearGuideSearch').addEventListener('click', () => { search.value = ''; render(); search.focus(); });
    document.addEventListener('click', event => {
      const button = event.target.closest('[data-reference-guide]');
      if (button) openGuide(button.dataset.referenceGuide, button);
      if (event.target.closest('#guideModalClose, [data-guide-close]')) closeGuide();
    });
    renderers.push(render);
    render();
  }

  const guideSidebar = document.querySelector('[data-guides-surface="sidebar"]');
  if (guideSidebar) {
    let tab = 'hypothesis', selected = null;
    const search = guideSidebar.querySelector('[data-guides-search]');
    const list = guideSidebar.querySelector('[data-guides-list]');
    const pane = guideSidebar.querySelector('[data-guides-detail]');
    const content = guideSidebar.querySelector('[data-guides-detail-content]');
    const listPane = guideSidebar.querySelector('[data-guides-content]');
    function render() {
      const guides = catalog.records.filter(entry => entry.kind === 'guide');
      all('[data-guides-count]', guideSidebar).forEach(el => { el.textContent = guides.filter(entry => entry.section === el.dataset.guidesCount).length; });
      const filtered = guides.filter(entry => entry.section === tab && matches(entry, search.value));
      list.innerHTML = filtered.map(entry => `<button class="guides-sidebar-item" type="button" data-sidebar-guide-id="${escape(entry.id)}"><span class="guides-sidebar-icon" data-category="${escape(entry.category)}">${escape(label(entry)[0])}</span><div class="guides-sidebar-item-content"><h4 class="guides-sidebar-item-title">${escape(entry.title)}</h4><p class="guides-sidebar-item-desc">${escape(entry.data.description)}</p><span class="guides-sidebar-item-category">${escape(label(entry))}</span></div></button>`).join('') || '<p>No guides match your search.</p>';
      const entry = byId.get(selected);
      pane.hidden = !entry;
      listPane.hidden = !!entry;
      if (entry) content.innerHTML = `<h3>${escape(entry.title)}</h3><p class="helper">${escape(entry.data.description)}</p>` + detail(entry);
    }
    guideSidebar.addEventListener('click', event => {
      const button = event.target.closest('[data-sidebar-guide-id]');
      if (button) { selected = button.dataset.sidebarGuideId; render(); }
      const nextTab = event.target.closest('[data-guides-tab]');
      if (nextTab) { tab = nextTab.dataset.guidesTab; selected = null; all('[data-guides-tab]', guideSidebar).forEach(el => el.classList.toggle('active', el === nextTab)); render(); }
      if (event.target.closest('[data-guides-back]')) { selected = null; render(); }
    });
    search.addEventListener('input', () => { selected = null; render(); });
    renderers.push(render);
    render();
  }

  let tooltip = document.getElementById('artifactTooltip');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.id = 'artifactTooltip';
    tooltip.className = 'artifact-tooltip';
    tooltip.hidden = true;
    document.body.append(tooltip);
  }
  tooltip.setAttribute('role', 'tooltip');
  let tooltipTarget = null;
  function hideTooltip() { tooltip.hidden = true; tooltip.classList.remove('visible'); tooltipTarget?.removeAttribute('aria-describedby'); tooltipTarget = null; }
  function showTooltip(target) {
    const entry = byId.get(target.dataset.artifact);
    if (!entry || entry.kind !== 'glossary') return;
    tooltipTarget = target;
    tooltip.innerHTML = `<div class="artifact-tooltip-content"><h4>${escape(entry.title)}</h4><p><span class="tooltip-label">What:</span> ${escape(entry.what)}</p><p><span class="tooltip-label">Why:</span> ${escape(entry.why)}</p></div>`;
    tooltip.hidden = false;
    tooltip.classList.add('visible');
    const box = target.getBoundingClientRect();
    tooltip.style.left = `${Math.max(8, Math.min(box.left, innerWidth - tooltip.offsetWidth - 8))}px`;
    tooltip.style.top = `${Math.max(8, Math.min(box.bottom + 8, innerHeight - tooltip.offsetHeight - 8))}px`;
    target.setAttribute('aria-describedby', tooltip.id);
  }
  const linkFrom = event => event.target.closest?.('.artifact-link[data-artifact]');
  document.addEventListener('mouseover', event => { const link = linkFrom(event); if (link) showTooltip(link); });
  document.addEventListener('mouseout', event => { if (linkFrom(event) && !tooltip.contains(event.relatedTarget)) hideTooltip(); });
  document.addEventListener('focusin', event => { const link = linkFrom(event); if (link) showTooltip(link); });
  document.addEventListener('focusout', event => { if (linkFrom(event)) hideTooltip(); });
  document.addEventListener('sifted:reference-changed', () => { if (tooltipTarget) showTooltip(tooltipTarget); });
  function followGlossary(link) {
    if (link.closest('[contenteditable="true"]')) return;
    const controller = glossaryControllers.find(item => item.sidebar) || glossaryControllers[0];
    if (controller) { controller.show(link.dataset.artifact); if (controller.sidebar) sidebarState('glossary', true); }
    else location.href = '/glossary?entry=' + encodeURIComponent(link.dataset.artifact);
    hideTooltip();
  }
  document.addEventListener('click', event => { const link = linkFrom(event); if (link) { event.preventDefault(); followGlossary(link); } });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') { hideTooltip(); closeGuide(); sidebarState('glossary', false); sidebarState('guides', false); }
    const link = linkFrom(event);
    if (link && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); followGlossary(link); }
  });
  const requested = new URL(location.href).searchParams.get('entry');
  if (requested) glossaryControllers.find(item => !item.sidebar)?.show(requested);
  if (requested && byId.get(requested)?.kind === 'guide' && modal) openGuide(requested);
})();
