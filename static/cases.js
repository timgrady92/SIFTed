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
  imageDisplay.addEventListener("input", () => {
    const next = imageDisplay.value.trim();
    imageInput.value = next;
    updateCaseNameFromPath(next);
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
