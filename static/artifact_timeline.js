const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const timezoneInput = document.getElementById("timelineTimezone");
const commandPreview = document.getElementById("commandPreview");
const runButton = document.getElementById("runTimeline");
const runStatus = document.getElementById("runStatus");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");
const runResults = document.getElementById("runResults");
const runResultsLinks = document.getElementById("runResultsLinks");
const openBrowser = document.getElementById("openBrowser");
const closeBrowser = document.getElementById("closeBrowser");
const browserDrawer = document.getElementById("browserDrawer");
const manualPath = document.getElementById("manualPath");
const useManualPath = document.getElementById("useManualPath");
const drawerList = document.getElementById("drawerList");
const drawerError = document.getElementById("drawerError");
const currentPathLabel = document.getElementById("currentPath");
const pathChips = Array.from(document.querySelectorAll(".path-chip"));

let currentPath = "/cases";
let currentRunId = "";

const buildCommand = () => {
  const sourcePath = imagePath.value.trim() || "<evidence_path>";
  const outputDir = outputPath.value.trim() || "<output_dir>";
  const timezone = timezoneInput?.value.trim() || "UTC";
  const storagePath = `${outputDir}/timeline.plaso`;
  const timelinePath = `${outputDir}/timeline.csv`;

  const log2timeline = ["log2timeline.py", "--storage_file", storagePath, sourcePath];
  const psort = [
    "psort.py",
    "-o",
    "l2tcsv",
    "-w",
    timelinePath,
    "--output_time_zone",
    timezone,
    storagePath,
  ];

  if (commandPreview) {
    commandPreview.textContent = `${log2timeline.join(" ")} && ${psort.join(" ")}`;
  }
};

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const renderResultsLink = (outputDir) => {
  if (!runResults || !runResultsLinks) {
    return;
  }
  if (!outputDir) {
    runResults.hidden = true;
    runResultsLinks.innerHTML = "";
    return;
  }
  const timelinePath = `${outputDir}/timeline.csv`;
  runResultsLinks.innerHTML = "";
  const link = document.createElement("a");
  link.className = "run-result-link";
  link.href = `/view-file?path=${encodeURIComponent(timelinePath)}`;
  link.textContent = "timeline.csv";
  runResultsLinks.appendChild(link);
  runResults.hidden = false;
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

const buildPayload = () => ({
  tool: "artifact-triage",
  case_id: document.getElementById("caseSelect")?.value || "",
  image_path: imagePath.value.trim(),
  output_path: outputPath.value.trim(),
  timezone: timezoneInput?.value.trim() || "UTC",
});

if (runButton) {
  runButton.addEventListener("click", async () => {
    if (runResults) {
      runResults.hidden = true;
    }
    runButton.disabled = true;
    runButton.textContent = "Running...";
    setRunStatus("Running timeline...", "neutral");
    try {
      const payload = buildPayload();
      const response = await fetch("/api/artifact-triage/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to run timeline.");
      }
      commandPreview.textContent = data.command || commandPreview.textContent;
      if (data.output_path) {
        outputPath.value = data.output_path;
      }
      renderResultsLink(data.output_path);
      currentRunId = data.run_id || "";
      if (currentRunId && window.registerActiveJob) {
        window.registerActiveJob({ id: currentRunId, tool: "Artifact Triage" });
      }
      setRunStatus("Running timeline...", "neutral");
      if (currentRunId && window.EventSource) {
        const source = new EventSource(`/api/run/${currentRunId}/events`);
        source.addEventListener("milestone", (event) => {
          const payload = JSON.parse(event.data || "{}");
          setRunStatus(payload.message || "Running...", "neutral");
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
          runButton.textContent = "Run timeline";
          runButton.disabled = false;
          source.close();
        });
        source.addEventListener("error", () => {
          setRunStatus("Run failed.", "error");
          runButton.textContent = "Run timeline";
          runButton.disabled = false;
          source.close();
        });
      } else {
        setRunStatus("Run started. Refresh to see results.", "neutral");
        runButton.textContent = "Run timeline";
        runButton.disabled = false;
      }
    } catch (error) {
      setRunStatus(error.message || "Run failed.", "error");
      runButton.textContent = "Run timeline";
      runButton.disabled = false;
    }
  });
}

if (openLog) {
  openLog.addEventListener("click", () => {
    toggleLogDrawer(true);
    loadFullLog();
  });
}

if (closeLog) {
  closeLog.addEventListener("click", () => toggleLogDrawer(false));
}

[imagePath, outputPath, timezoneInput].forEach((input) => {
  if (!input) {
    return;
  }
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

buildCommand();
