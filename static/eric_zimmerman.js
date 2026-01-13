const toolDataElement = document.getElementById("ezToolData");
const toolData = toolDataElement ? JSON.parse(toolDataElement.textContent || "[]") : [];
const toolsById = toolData.reduce((acc, tool) => {
  acc[tool.id] = tool;
  return acc;
}, {});

const toolButtons = Array.from(document.querySelectorAll(".ez-tool-card"));
const toolGrid = document.getElementById("ezToolGrid");
const toggleCatalog = document.getElementById("toggleEzCatalog");
const toolName = document.getElementById("ezToolName");
const toolDescription = document.getElementById("ezToolDescription");
const toolHint = document.getElementById("ezToolHint");
const toolOutput = document.getElementById("ezToolOutput");
const toolStatus = document.getElementById("ezToolStatus");

const sourcePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const caseSelect = document.getElementById("caseSelect");
const commandPreview = document.getElementById("commandPreview");
const runButton = document.getElementById("runEzTool");
const runStatus = document.getElementById("runStatus");
const runResults = document.getElementById("runResults");
const runResultsLinks = document.getElementById("runResultsLinks");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");

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
let selectedToolId = "";

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const renderResultsLink = (outputFile) => {
  if (!runResults || !runResultsLinks) {
    return;
  }
  if (!outputFile) {
    runResults.hidden = true;
    runResultsLinks.innerHTML = "";
    return;
  }
  runResultsLinks.innerHTML = "";
  const link = document.createElement("a");
  link.className = "run-result-link";
  link.href = `/view-file?path=${encodeURIComponent(outputFile)}`;
  link.textContent = outputFile.split("/").pop() || "results.csv";
  runResultsLinks.appendChild(link);
  runResults.hidden = false;
};

const updateOutputForTool = (toolId) => {
  if (!caseSelect) {
    return;
  }
  caseSelect.dataset.tool = `eric-zimmerman/${toolId}`;
  const event = new Event("change", { bubbles: true });
  caseSelect.dispatchEvent(event);
};

const buildCommand = () => {
  if (!commandPreview) {
    return;
  }
  const tool = toolsById[selectedToolId];
  if (!tool) {
    commandPreview.textContent = "Select a parser to preview the command.";
    return;
  }
  const source = sourcePath?.value.trim() || "<source_path>";
  const outputDir = outputPath?.value.trim() || "<output_dir>";
  const binary = tool.binary_display || tool.label;
  let inputFlag = "-f";
  let note = "";
  if (tool.input_mode === "dir") {
    inputFlag = "-d";
  } else if (tool.input_mode === "file_or_dir") {
    inputFlag = source.endsWith("/") ? "-d" : "-f";
    note = " # use -d for directories";
  }
  const args = [
    binary,
    inputFlag,
    source,
    "--csv",
    outputDir,
    "--csvf",
    tool.csv_name,
  ];
  commandPreview.textContent = `${args.join(" ")}${note}`;
};

const selectTool = (toolId) => {
  const tool = toolsById[toolId];
  if (!tool) {
    return;
  }
  selectedToolId = toolId;
  toolButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.toolId === toolId);
  });
  if (toolName) {
    toolName.textContent = tool.label;
  }
  if (toolDescription) {
    toolDescription.textContent = tool.description;
  }
  if (toolHint) {
    toolHint.textContent = tool.input_hint;
  }
  if (toolOutput) {
    toolOutput.textContent = `Output: ${tool.csv_name} (CSV)`;
  }
  if (toolStatus) {
    toolStatus.textContent = tool.installed ? "Installed" : "Missing from PATH";
    toolStatus.classList.toggle("muted", !tool.installed);
  }
  if (runButton) {
    runButton.textContent = `Run ${tool.label}`;
    runButton.disabled = !tool.installed;
  }
  if (!tool.installed) {
    setRunStatus(`${tool.label} is not available on PATH.`, "error");
  } else {
    setRunStatus("Ready to run.", "neutral");
  }
  renderResultsLink("");
  updateOutputForTool(toolId);
  buildCommand();
};

const selectInitialTool = () => {
  const curated = toolData.find((tool) => tool.curated);
  const fallback = toolData[0];
  const initial = curated || fallback;
  if (initial) {
    selectTool(initial.id);
  }
};

const toggleDrawer = (isOpen) => {
  if (!browserDrawer) {
    return;
  }
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

toolButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const toolId = button.dataset.toolId || "";
    if (toolId) {
      selectTool(toolId);
    }
  });
});

if (toggleCatalog && toolGrid) {
  toggleCatalog.addEventListener("click", () => {
    const showAll = toolGrid.dataset.showAll === "true";
    toolGrid.dataset.showAll = String(!showAll);
    toggleCatalog.textContent = showAll ? "Show all tools" : "Show curated tools";
    if (!showAll) {
      return;
    }
    const selected = toolsById[selectedToolId];
    if (selected && !selected.curated) {
      const curated = toolData.find((tool) => tool.curated);
      if (curated) {
        selectTool(curated.id);
      }
    }
  });
}

if (openBrowser) {
  openBrowser.addEventListener("click", () => {
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
    if (sourcePath) {
      sourcePath.value = entryPath;
    }
    toggleDrawer(false);
    buildCommand();
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
    if (manualPath.value.trim() && sourcePath) {
      sourcePath.value = manualPath.value.trim();
      manualPath.value = "";
      toggleDrawer(false);
      buildCommand();
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

if (runButton) {
  runButton.addEventListener("click", async () => {
    const tool = toolsById[selectedToolId];
    if (!tool) {
      setRunStatus("Select a parser first.", "error");
      return;
    }
    if (!tool.installed) {
      setRunStatus(`${tool.label} is not available on PATH.`, "error");
      return;
    }
    runButton.disabled = true;
    runButton.textContent = "Running...";
    setRunStatus(`Running ${tool.label}...`, "neutral");

    try {
      const response = await fetch("/api/eric-zimmerman/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool_id: selectedToolId,
          case_id: caseSelect?.value || "",
          source_path: sourcePath?.value.trim() || "",
          output_path: outputPath?.value.trim() || "",
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to run parser.");
      }
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
      if (data.output_file) {
        renderResultsLink(data.output_file);
      }
      if (data.command && commandPreview) {
        commandPreview.textContent = data.command;
      }
      currentRunId = data.run_id || "";
      if (currentRunId && window.registerActiveJob) {
        window.registerActiveJob({ id: currentRunId, tool: tool.label });
      }
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
          runButton.textContent = `Run ${tool.label}`;
          runButton.disabled = false;
          source.close();
        });
        source.addEventListener("error", () => {
          setRunStatus("Run failed.", "error");
          runButton.textContent = `Run ${tool.label}`;
          runButton.disabled = false;
          source.close();
        });
      } else {
        setRunStatus("Run started. Refresh to see results.", "neutral");
        runButton.textContent = `Run ${tool.label}`;
        runButton.disabled = false;
      }
    } catch (error) {
      setRunStatus(error.message || "Run failed.", "error");
      runButton.textContent = `Run ${tool.label}`;
      runButton.disabled = false;
    }
  });
}

[sourcePath, outputPath].forEach((input) => {
  if (!input) {
    return;
  }
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

if (caseSelect) {
  caseSelect.addEventListener("change", buildCommand);
}

selectInitialTool();
buildCommand();
