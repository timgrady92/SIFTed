const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const quickFlag = document.getElementById("quickFlag");
const verboseFlag = document.getElementById("verboseFlag");
const safeMode = document.getElementById("safeMode");
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
const runButton = document.getElementById("runForemost");
const resultCarved = document.getElementById("resultCarved");
const resultAudit = document.getElementById("resultAudit");
const resultSummary = document.getElementById("resultSummary");
const runStatus = document.getElementById("runStatus");
const runLog = document.getElementById("runLog");
const milestonesList = document.getElementById("milestoneList");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");

let currentRunId = "";

let currentPath = "/cases";

const buildCommand = () => {
  const types = Array.from(document.querySelectorAll(".chip input:checked"))
    .map((input) => mapType(input.value))
    .join(",");

  const args = [
    "foremost",
    "-i",
    imagePath.value.trim() || "<image_path>",
    "-o",
    outputPath.value.trim() || "<output_dir>",
  ];

  if (types) {
    args.push("-t", types);
  }

  if (quickFlag.checked) {
    args.push("-q");
  }

  if (verboseFlag.checked) {
    args.push("-v");
  }

  if (safeMode && safeMode.checked) {
    args.push("-T");
    args.push("# safe mode: 10s per type");
  }

  commandPreview.textContent = args.join(" ");
};

const mapType = (value) => {
  if (value === "jpeg") {
    return "jpg";
  }
  return value;
};

const buildPayload = () => ({
  tool: "foremost",
  case_id: caseSelect?.value || "",
  image_path: imagePath.value.trim(),
  output_path: outputPath.value.trim(),
  types: Array.from(document.querySelectorAll(".chip input:checked")).map(
    (input) => mapType(input.value),
  ),
  quick: quickFlag.checked,
  verbose: verboseFlag.checked,
  safe_mode: safeMode?.checked || false,
});

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const setRunLog = (text) => {
  if (!runLog) {
    return;
  }
  runLog.textContent = text || "";
};

const appendMilestone = (message) => {
  if (!milestonesList) {
    return;
  }
  const item = document.createElement("li");
  item.textContent = message;
  milestonesList.prepend(item);
  const items = milestonesList.querySelectorAll("li");
  if (items.length > 6) {
    items[items.length - 1].remove();
  }
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
  autoImage = "";
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

[runButton].forEach((button) => {
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Running...";
    setRunStatus("Running Foremost...", "neutral");
    setRunLog("");
    try {
      const response = await fetch("/api/foremost/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to run Foremost.");
      }
      commandPreview.textContent = data.command || commandPreview.textContent;
      if (data.output_path) {
        outputPath.value = data.output_path;
      }
      currentRunId = data.run_id || "";
      if (currentRunId && window.registerActiveJob) {
        window.registerActiveJob({ id: currentRunId, tool: "Foremost" });
      }
      if (resultCarved) {
        resultCarved.textContent = `${data.output_path || outputPath.value}/`;
      }
      if (resultAudit) {
        resultAudit.textContent = "audit.txt";
      }
      if (resultSummary) {
        resultSummary.textContent = "output.txt";
      }
      if (milestonesList) {
        milestonesList.innerHTML = "";
      }
      setRunStatus("Running Foremost...", "neutral");

      if (currentRunId && window.EventSource) {
        const source = new EventSource(`/api/run/${currentRunId}/events`);
        source.addEventListener("milestone", (event) => {
          const payload = JSON.parse(event.data || "{}");
          appendMilestone(payload.message || "Milestone");
        });
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
          button.textContent = "Run Foremost";
          button.disabled = false;
          source.close();
        });
        source.addEventListener("error", () => {
          setRunStatus("Run failed.", "error");
          button.textContent = "Run Foremost";
          button.disabled = false;
          source.close();
        });
      } else {
        setRunStatus("Run started. Refresh to see results.", "neutral");
        button.textContent = "Run Foremost";
        button.disabled = false;
      }
    } catch (error) {
      setRunStatus(error.message || "Run failed.", "error");
      setRunLog("");
      button.textContent = "Run Foremost";
      button.disabled = false;
    }
  });
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

[imagePath, outputPath, quickFlag, verboseFlag, safeMode].forEach((input) => {
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
});

buildCommand();
