const browseButton = document.getElementById("caseBrowse");
const drawer = document.getElementById("browserDrawer");
const drawerList = document.getElementById("drawerList");
const drawerError = document.getElementById("drawerError");
const currentPathLabel = document.getElementById("currentPath");
const closeBrowser = document.getElementById("closeBrowser");
const pathChips = Array.from(document.querySelectorAll(".path-chip"));
const manualPath = document.getElementById("manualPath");
const useManualPath = document.getElementById("useManualPath");
const imageInput = document.getElementById("caseImagePath");
const imageDisplay = document.getElementById("caseImagePathDisplay");
const caseNameInput = document.getElementById("caseName");

let currentPath = "/cases";
let autoCaseName = "";

const toggleDrawer = (isOpen) => {
  drawer.classList.toggle("open", isOpen);
  drawer.setAttribute("aria-hidden", String(!isOpen));
};

const renderDrawer = (data) => {
  drawerList.innerHTML = "";
  drawerError.hidden = true;
  currentPathLabel.textContent = data.path;

  if (data.parent) {
    const upButton = document.createElement("button");
    upButton.className = "drawer-item";
    upButton.dataset.type = "dir";
    upButton.dataset.path = data.parent;
    upButton.textContent = "..";
    drawerList.appendChild(upButton);
  }

  data.entries.forEach((entry) => {
    const button = document.createElement("button");
    button.className = "drawer-item";
    button.dataset.type = entry.type;
    button.dataset.path = entry.path;
    button.textContent = entry.name;
    drawerList.appendChild(button);
  });
};

const loadDirectory = async (path) => {
  try {
    const response = await fetch(`/api/browse?path=${encodeURIComponent(path)}`);
    if (!response.ok) {
      throw new Error("browse-failed");
    }
    const data = await response.json();
    currentPath = data.path;
    renderDrawer(data);
  } catch (error) {
    drawerError.hidden = false;
  }
};

const updateImagePath = (path) => {
  if (!path) {
    return;
  }
  imageInput.value = path;
  imageDisplay.value = path;
  updateCaseNameFromPath(path);
};

const buildCaseName = (path) => {
  const trimmed = path.trim();
  if (!trimmed) {
    return "";
  }
  const fileName = trimmed.split("/").filter(Boolean).pop() || "case";
  const stamp = new Date()
    .toISOString()
    .replace(/[-:]/g, "")
    .slice(0, 15)
    .replace("T", "-");
  return `${fileName} ${stamp}`;
};

const updateCaseNameFromPath = (path) => {
  if (!caseNameInput) {
    return;
  }
  const next = buildCaseName(path);
  if (!caseNameInput.value.trim() || caseNameInput.value.trim() === autoCaseName) {
    caseNameInput.value = next;
    autoCaseName = next;
  }
};

if (browseButton) {
  browseButton.addEventListener("click", () => {
    toggleDrawer(true);
    loadDirectory(currentPath);
  });
}

if (closeBrowser) {
  closeBrowser.addEventListener("click", () => toggleDrawer(false));
}

if (drawerList) {
  drawerList.addEventListener("click", (event) => {
    const target = event.target.closest(".drawer-item");
    if (!target) {
      return;
    }
    const entryPath = target.dataset.path || "";
    const entryType = target.dataset.type || "file";
    if (entryType === "dir") {
      loadDirectory(entryPath);
      return;
    }
    updateImagePath(entryPath);
    toggleDrawer(false);
  });
}

pathChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    const nextPath = chip.dataset.path || "/cases";
    loadDirectory(nextPath);
  });
});

if (useManualPath) {
  useManualPath.addEventListener("click", () => {
    if (manualPath.value.trim()) {
      updateImagePath(manualPath.value.trim());
      manualPath.value = "";
      toggleDrawer(false);
    }
  });
}

if (imageDisplay) {
  let imageInputTimeout;
  imageDisplay.addEventListener("input", () => {
    // Debounce input to avoid expensive operations on every keystroke
    clearTimeout(imageInputTimeout);
    imageInputTimeout = setTimeout(() => {
      const next = imageDisplay.value.trim();
      imageInput.value = next;
      updateCaseNameFromPath(next);
    }, 150);
  });
}

if (caseNameInput) {
  caseNameInput.addEventListener("input", () => {
    if (caseNameInput.value.trim() !== autoCaseName) {
      autoCaseName = "";
    }
  });
}

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

// Artifact management
const artifactModal = document.getElementById("addArtifactModal");
const artifactForm = document.getElementById("addArtifactForm");
const artifactCaseIdInput = document.getElementById("artifactCaseId");
const artifactPathInput = document.getElementById("artifactPath");
const artifactTypeSelect = document.getElementById("artifactType");
const artifactLabelInput = document.getElementById("artifactLabel");
const closeArtifactModalBtn = document.getElementById("closeArtifactModal");
const cancelArtifactBtn = document.getElementById("cancelArtifact");
const browseArtifactBtn = document.getElementById("browseArtifact");

let artifactBrowseMode = false;

const toggleArtifactModal = (isOpen) => {
  if (!artifactModal) return;
  artifactModal.classList.toggle("open", isOpen);
  artifactModal.setAttribute("aria-hidden", String(!isOpen));
  if (!isOpen) {
    artifactForm?.reset();
    artifactCaseIdInput.value = "";
  }
};

const openAddArtifactModal = (caseId) => {
  if (!caseId) return;
  artifactCaseIdInput.value = caseId;
  toggleArtifactModal(true);
};

// Event delegation for add artifact buttons
document.addEventListener("click", (event) => {
  const addBtn = event.target.closest(".add-artifact-btn");
  if (addBtn) {
    const caseId = addBtn.dataset.caseId;
    openAddArtifactModal(caseId);
    return;
  }

  const removeBtn = event.target.closest(".artifact-remove");
  if (removeBtn) {
    event.stopPropagation();
    const artifactId = removeBtn.dataset.artifactId;
    const caseContainer = removeBtn.closest(".case-artifacts");
    const caseId = caseContainer?.dataset.caseId;
    if (artifactId && caseId) {
      removeArtifact(caseId, artifactId, removeBtn.closest(".artifact-chip"));
    }
  }
});

if (closeArtifactModalBtn) {
  closeArtifactModalBtn.addEventListener("click", () => toggleArtifactModal(false));
}

if (cancelArtifactBtn) {
  cancelArtifactBtn.addEventListener("click", () => toggleArtifactModal(false));
}

// Browse for artifact path - reuse the existing drawer
if (browseArtifactBtn && drawer) {
  browseArtifactBtn.addEventListener("click", () => {
    artifactBrowseMode = true;
    toggleDrawer(true);
    loadDirectory(currentPath);
  });
}

// Override drawer item click when in artifact browse mode
if (drawerList) {
  const originalHandler = drawerList.onclick;
  drawerList.addEventListener("click", (event) => {
    if (!artifactBrowseMode) return;
    const target = event.target.closest(".drawer-item");
    if (!target) return;
    const entryPath = target.dataset.path || "";
    const entryType = target.dataset.type || "file";
    if (entryType === "dir") {
      loadDirectory(entryPath);
      return;
    }
    if (artifactPathInput) {
      artifactPathInput.value = entryPath;
    }
    artifactBrowseMode = false;
    toggleDrawer(false);
    event.stopPropagation();
  }, true);
}

// Allow useManualPath in artifact browse mode
if (useManualPath) {
  const originalUseManual = useManualPath.onclick;
  useManualPath.addEventListener("click", () => {
    if (!artifactBrowseMode) return;
    if (manualPath.value.trim() && artifactPathInput) {
      artifactPathInput.value = manualPath.value.trim();
      manualPath.value = "";
      artifactBrowseMode = false;
      toggleDrawer(false);
    }
  }, true);
}

// Submit artifact form
if (artifactForm) {
  artifactForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const caseId = artifactCaseIdInput?.value;
    const path = artifactPathInput?.value?.trim();
    const type = artifactTypeSelect?.value || "";
    const label = artifactLabelInput?.value?.trim() || "";

    if (!caseId || !path) return;

    try {
      const response = await fetch(`/api/case/${caseId}/artifacts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, type, label }),
      });
      const data = await response.json();
      if (!response.ok) {
        alert(data.error || "Failed to add artifact.");
        return;
      }
      // Reload page to show new artifact
      window.location.reload();
    } catch (error) {
      alert("Failed to add artifact: " + error.message);
    }
  });
}

const removeArtifact = async (caseId, artifactId, chipElement) => {
  if (!confirm("Remove this artifact from the case?")) return;

  try {
    const response = await fetch(`/api/case/${caseId}/artifacts/${artifactId}`, {
      method: "DELETE",
    });
    const data = await response.json();
    if (!response.ok) {
      alert(data.error || "Failed to remove artifact.");
      return;
    }
    // Remove the chip from DOM
    if (chipElement) {
      const group = chipElement.closest(".artifact-group");
      chipElement.remove();
      // If group is now empty, remove it too
      if (group && !group.querySelector(".artifact-chip")) {
        group.remove();
      }
      // If no more artifacts, show empty message
      const container = document.querySelector(`.case-artifacts[data-case-id="${caseId}"]`);
      if (container && !container.querySelector(".artifact-chip")) {
        const groups = container.querySelector(".artifact-groups");
        if (groups) {
          groups.innerHTML = '<p class="case-empty artifacts-empty">No artifacts yet. Add evidence files to this case.</p>';
        }
      }
    }
  } catch (error) {
    alert("Failed to remove artifact: " + error.message);
  }
};
