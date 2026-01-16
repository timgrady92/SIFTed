const tooling = window.SiftedTooling;

// Tool data from embedded JSON
const toolDataElement = document.getElementById("ezToolData");
const toolData = toolDataElement ? JSON.parse(toolDataElement.textContent || "[]") : [];
const toolsById = toolData.reduce((acc, tool) => {
  acc[tool.id] = tool;
  return acc;
}, {});

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.imagePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const toolButtons = Array.from(document.querySelectorAll(".ez-tool-card"));
const toolGrid = document.getElementById("ezToolGrid");
const toggleCatalog = document.getElementById("toggleEzCatalog");
const toolName = document.getElementById("ezToolName");
const toolDescription = document.getElementById("ezToolDescription");
const toolHint = document.getElementById("ezToolHint");
const toolOutput = document.getElementById("ezToolOutput");
const toolStatus = document.getElementById("ezToolStatus");
const runButton = document.getElementById("runEzTool");
const runResults = document.getElementById("runResults");
const runResultsLinks = document.getElementById("runResultsLinks");

let currentRunId = "";
let selectedToolId = "";

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
    runButton.dataset.defaultLabel = runButton.textContent;
    runButton.disabled = !tool.installed;
  }
  if (!tool.installed && tooling) {
    tooling.setRunStatus(runStatus, `${tool.label} is not available on PATH.`, "error");
  } else if (tooling) {
    tooling.setRunStatus(runStatus, "Ready to run.", "neutral");
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

// Initialize drawers using helper
if (tooling) {
  tooling.initializeDrawers({
    ...common,
    getRunId: () => currentRunId,
    onSelectPath: (path) => {
      if (sourcePath) {
        sourcePath.value = path;
      }
      buildCommand();
    },
  });
}

// Tool button handlers
toolButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const toolId = button.dataset.toolId || "";
    if (toolId) {
      selectTool(toolId);
    }
  });
});

// Catalog toggle
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

// Run button handler - custom because of dynamic tool selection
if (runButton && tooling) {
  const resetRunButton = () => {
    runButton.textContent = runButton.dataset.defaultLabel || runButton.textContent || "Run";
    runButton.disabled = false;
  };

  runButton.addEventListener("click", async () => {
    const tool = toolsById[selectedToolId];
    if (!tool) {
      tooling.setRunStatus(runStatus, "Select a parser first.", "error");
      return;
    }
    if (!tool.installed) {
      tooling.setRunStatus(runStatus, `${tool.label} is not available on PATH.`, "error");
      return;
    }
    runButton.disabled = true;
    runButton.textContent = "Running...";
    tooling.setRunStatus(runStatus, `Running ${tool.label}...`, "neutral");

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
        tooling.attachRunEvents(currentRunId, {
          onStatus: (payload) => {
            tooling.setRunStatus(runStatus, payload.message || "Running...", "neutral");
          },
          onDone: (payload) => {
            const exitCode = Number(payload.message || 0);
            const { message, tone } = tooling.getCompletionStatus(exitCode);
            tooling.setRunStatus(runStatus, message, tone);
            resetRunButton();
          },
          onError: () => {
            tooling.setRunStatus(runStatus, tooling.RUN_MESSAGES.FAILED, "error");
            resetRunButton();
          },
        });
      } else {
        tooling.setRunStatus(runStatus, tooling.RUN_MESSAGES.STARTED_REFRESH, "neutral");
        resetRunButton();
      }
    } catch (error) {
      tooling.setRunStatus(runStatus, error.message || tooling.RUN_MESSAGES.FAILED, "error");
      resetRunButton();
    }
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners([sourcePath, outputPath], buildCommand);
}

if (caseSelect) {
  caseSelect.addEventListener("change", buildCommand);
}

selectInitialTool();
buildCommand();
