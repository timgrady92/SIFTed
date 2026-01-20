// Tab switching
const tabButtons = Array.from(document.querySelectorAll("[data-tab]"));
const tabPanels = Array.from(document.querySelectorAll("[data-tab-panel]"));
const guideCount = document.getElementById("guideCount");
const guideEmpty = document.getElementById("guideEmpty");
const clearGuideSearch = document.getElementById("clearGuideSearch");
const guideModal = document.getElementById("guideModal");
const guideModalTitle = document.getElementById("guideModalTitle");
const guideModalSummary = document.getElementById("guideModalSummary");
const guideModalCategory = document.getElementById("guideModalCategory");
const guideModalBody = document.getElementById("guideModalBody");
const guideModalClose = document.getElementById("guideModalClose");
let lastFocusedGuide = null;

// Guide search
const guideSearch = document.getElementById("guideSearch");
const guideCards = Array.from(document.querySelectorAll(".guide-card"));

const formatCategoryLabel = (value) => {
  if (!value) return "Guide";
  return value
    .split("-")
    .map((chunk) => chunk.charAt(0).toUpperCase() + chunk.slice(1))
    .join(" ");
};

const ensureGuidePill = (card) => {
  const container = card.querySelector(".guide-toggle-content > div");
  if (!container || container.querySelector(".guide-pill")) {
    return;
  }
  const category = card.dataset.category || "info";
  const pill = document.createElement("span");
  pill.className = "guide-pill";
  pill.dataset.category = category;
  pill.textContent = formatCategoryLabel(category);
  container.insertBefore(pill, container.firstChild);
};

const ensureGuideToggleLabel = (toggle) => {
  if (!toggle || toggle.querySelector(".guide-toggle-label")) {
    return;
  }
  const chevron = toggle.querySelector(".toggle-icon.chevron");
  if (!chevron) {
    return;
  }
  const cta = document.createElement("span");
  cta.className = "guide-toggle-cta";
  const label = document.createElement("span");
  label.className = "guide-toggle-label";
  label.textContent = "Open guide";
  cta.appendChild(label);
  cta.appendChild(chevron);
  toggle.appendChild(cta);
};

const getActivePanel = () => tabPanels.find((panel) => !panel.hidden) || tabPanels[0];

const updateGuideMeta = () => {
  const activePanel = getActivePanel();
  if (!activePanel) {
    return;
  }
  const cards = Array.from(activePanel.querySelectorAll(".guide-card"));
  const visibleCards = cards.filter((card) => !card.classList.contains("search-hidden"));
  if (guideCount) {
    guideCount.textContent = `${visibleCards.length} of ${cards.length} guides`;
  }
  if (guideEmpty) {
    guideEmpty.hidden = visibleCards.length > 0;
  }
};

const setActiveTab = (tabId, persist = true) => {
  tabButtons.forEach((button) => {
    const isActive = button.dataset.tab === tabId;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });
  tabPanels.forEach((panel) => {
    const isActive = panel.dataset.tabPanel === tabId;
    panel.hidden = !isActive;
  });
  if (persist) {
    localStorage.setItem("sifted.guides.tab", tabId);
  }
  updateGuideMeta();
};

const lockScroll = (locked) => {
  document.body.classList.toggle("modal-open", locked);
};

const initGuideModals = () => {
  guideCards.forEach((card) => {
    ensureGuidePill(card);
    const toggle = card.querySelector(".guide-toggle");
    ensureGuideToggleLabel(toggle);
    if (toggle) {
      toggle.addEventListener("click", () => {
        openGuideModal(card);
      });
    }
  });
};

initGuideModals();

if (tabButtons.length) {
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.tab) {
        setActiveTab(button.dataset.tab);
      }
    });
  });
  // Restore saved tab or use default
  const savedTab = localStorage.getItem("sifted.guides.tab");
  const validTabs = tabButtons.map((b) => b.dataset.tab);
  const initialTab = savedTab && validTabs.includes(savedTab)
    ? savedTab
    : tabButtons[0].dataset.tab;
  setActiveTab(initialTab, false);
}

if (guideSearch) {
  // Pre-cache search data to avoid repeated DOM queries
  const guidesSearchIndex = guideCards.map((card) => ({
    card,
    searchText: [
      card.querySelector("h2")?.textContent || "",
      card.querySelector(".helper")?.textContent || "",
      card.dataset.keywords || "",
      card.dataset.category || ""
    ].join(" ").toLowerCase()
  }));

  let searchTimeout;
  guideSearch.addEventListener("input", () => {
    // Debounce search to avoid blocking main thread on every keystroke
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      const query = guideSearch.value.toLowerCase().trim();
      guidesSearchIndex.forEach(({ card, searchText }) => {
        const matches = !query || searchText.includes(query);
        card.classList.toggle("search-hidden", !matches);
      });
      if (clearGuideSearch) {
        clearGuideSearch.hidden = query.length === 0;
      }
      updateGuideMeta();
    }, 150);
  });
}

if (clearGuideSearch && guideSearch) {
  clearGuideSearch.addEventListener("click", () => {
    guideSearch.value = "";
    guideSearch.dispatchEvent(new Event("input"));
    guideSearch.focus();
  });
}

updateGuideMeta();

function openGuideModal(card) {
  if (!guideModal) {
    return;
  }
  lastFocusedGuide = card.querySelector(".guide-toggle");
  const title = card.querySelector("h2")?.textContent?.trim() || "Guide";
  const summary = card.querySelector(".guide-toggle .helper")?.textContent?.trim() || "";
  const category = card.dataset.category || "info";
  const body = card.querySelector(".guide-body");

  if (guideModalTitle) {
    guideModalTitle.textContent = title;
  }
  if (guideModalSummary) {
    guideModalSummary.textContent = summary;
    guideModalSummary.hidden = summary.length === 0;
  }
  if (guideModalCategory) {
    guideModalCategory.dataset.category = category;
    guideModalCategory.textContent = formatCategoryLabel(category);
  }
  if (guideModalBody) {
    // Use cloneNode instead of innerHTML for better performance
    // (avoids serialization/deserialization overhead)
    guideModalBody.innerHTML = "";
    if (body) {
      const clone = body.cloneNode(true);
      while (clone.firstChild) {
        guideModalBody.appendChild(clone.firstChild);
      }
    }
    // Note: artifact tooltips use event delegation, no initialization needed
  }

  guideModal.classList.add("open");
  guideModal.setAttribute("aria-hidden", "false");
  lockScroll(true);
  if (guideModalClose) {
    guideModalClose.focus();
  }
}

function closeGuideModal() {
  if (!guideModal) {
    return;
  }
  guideModal.classList.remove("open");
  guideModal.setAttribute("aria-hidden", "true");
  lockScroll(false);
  if (lastFocusedGuide) {
    lastFocusedGuide.focus();
  }
}

if (guideModalClose) {
  guideModalClose.addEventListener("click", closeGuideModal);
}

if (guideModal) {
  guideModal.addEventListener("click", (event) => {
    if (event.target.matches("[data-guide-close]")) {
      closeGuideModal();
    }
  });
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && guideModal?.classList.contains("open")) {
    closeGuideModal();
  }
});
