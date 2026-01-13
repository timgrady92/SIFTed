const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const commandPreview = document.getElementById("commandPreview");
const openBrowser = document.getElementById("openBrowser");
const closeBrowser = document.getElementById("closeBrowser");
const browserDrawer = document.getElementById("browserDrawer");
const manualPath = document.getElementById("manualPath");
const useManualPath = document.getElementById("useManualPath");
const drawerList = document.getElementById("drawerList");
const drawerError = document.getElementById("drawerError");
const currentPathLabel = document.getElementById("currentPath");
const pathChips = Array.from(document.querySelectorAll(".path-chip"));
const caseSelect = document.getElementById("caseSelect");
const runButton = document.getElementById("runScalpel");
const runStatus = document.getElementById("runStatus");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");
const organizeByType = document.getElementById("organizeByType");

let currentPath = "/cases";
let currentRunId = "";

const gatherTypes = () => {
  const types = [];
  document.querySelectorAll(".focus-types input:checked").forEach((input) => {
    const typeList = input.dataset.types || "";
    typeList.split(",").forEach((entry) => {
      const trimmed = entry.trim();
      if (trimmed) {
        types.push(trimmed);
      }
    });
  });
  return types;
};

const buildCommand = () => {
  const types = gatherTypes();
  const args = [
    "scalpel",
    "-c",
    "<generated_config>",
    "-o",
    outputPath.value.trim() || "<output_dir>",
  ];
  if (!organizeByType.checked) {
    args.push("-O");
  }
  args.push(imagePath.value.trim() || "<image_path>");
  if (types.length) {
    args.push(`# ${types.join(", ")}`);
  }
  commandPreview.textContent = args.join(" ");
};

const toggleDrawer = (isOpen) => {
  browserDrawer.classList.toggle("open", isOpen);
  browserDrawer.setAttribute("aria-hidden", String(!isOpen));
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

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const toggleLogDrawer = (isOpen) => {
  if (!logDrawer) {
    return;
  }
  logDrawer.classList.toggle("open", isOpen);
  logDrawer.setAttribute("aria-hidden", String(!isOpen));
};

const loadFullLog = async () => {
  if (!currentRunId || !logDrawerContent) {
    return;
  }
  if (logDrawerStatus) {
    logDrawerStatus.textContent = "Loading log...";
  }
  try {
    const response = await fetch(`/api/run/${currentRunId}/log`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Unable to load log.");
    }
    logDrawerContent.textContent = data.log || "No log output.";
    if (logDrawerStatus) {
      logDrawerStatus.textContent = "";
    }
  } catch (error) {
    if (logDrawerStatus) {
      logDrawerStatus.textContent = error.message;
    }
    if (logDrawerContent) {
      logDrawerContent.textContent = "";
    }
  }
};

openBrowser.addEventListener("click", () => {
  toggleDrawer(true);
  loadDirectory(currentPath);
});
closeBrowser.addEventListener("click", () => toggleDrawer(false));

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
  imagePath.value = entryPath;
  toggleDrawer(false);
  buildCommand();
});

pathChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    const nextPath = chip.dataset.path || "/cases";
    loadDirectory(nextPath);
  });
});

useManualPath.addEventListener("click", () => {
  if (manualPath.value.trim()) {
    imagePath.value = manualPath.value.trim();
    manualPath.value = "";
    toggleDrawer(false);
    buildCommand();
  }
});

const buildPayload = () => {
  return {
    tool: "scalpel",
    case_id: caseSelect?.value || "",
    image_path: imagePath.value.trim(),
    output_path: outputPath.value.trim(),
    types: gatherTypes(),
    organize: organizeByType.checked,
  };
};

runButton.addEventListener("click", async () => {
  runButton.disabled = true;
  runButton.textContent = "Running...";
  setRunStatus("Running Scalpel...", "neutral");
  try {
    const response = await fetch("/api/scalpel/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildPayload()),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Unable to run Scalpel.");
    }
    commandPreview.textContent = data.command || commandPreview.textContent;
    if (data.output_path) {
      outputPath.value = data.output_path;
    }
    currentRunId = data.run_id || "";
    if (currentRunId && window.registerActiveJob) {
      window.registerActiveJob({ id: currentRunId, tool: "Scalpel" });
    }
    setRunStatus("Running Scalpel...", "neutral");
    if (currentRunId && window.EventSource) {
      const source = new EventSource(`/api/run/${currentRunId}/events`);
      source.addEventListener("status", (event) => {
        const payload = JSON.parse(event.data || "{}");
        setRunStatus(payload.message || "Running...", "neutral");
      });
      source.addEventListener("done", (event) => {
        const payload = JSON.parse(event.data || "{}");
        const exitCode = Number(payload.message || 0);
        setRunStatus(
          exitCode === 0 ? "Run completed." : "Run completed with errors.",
          exitCode === 0 ? "success" : "error",
        );
        runButton.textContent = "Run Scalpel";
        runButton.disabled = false;
        source.close();
      });
      source.addEventListener("error", () => {
        setRunStatus("Run failed.", "error");
        runButton.textContent = "Run Scalpel";
        runButton.disabled = false;
        source.close();
      });
    } else {
      setRunStatus("Run started. Refresh to see results.", "neutral");
      runButton.textContent = "Run Scalpel";
      runButton.disabled = false;
    }
  } catch (error) {
    setRunStatus(error.message || "Run failed.", "error");
    runButton.textContent = "Run Scalpel";
    runButton.disabled = false;
  }
});

if (openLog) {
  openLog.addEventListener("click", () => {
    toggleLogDrawer(true);
    loadFullLog();
  });
}

if (closeLog) {
  closeLog.addEventListener("click", () => toggleLogDrawer(false));
}

[imagePath, outputPath, organizeByType].forEach((input) => {
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
});

buildCommand();
