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
const sourcePath = common.sourcePath;
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

const updateOutputForTool = (toolId) => {
  if (!caseSelect) {
    return;
  }
  caseSelect.dataset.tool = `eric-zimmerman/${toolId}`;
  const event = new Event("change", { bubbles: true });
  caseSelect.dispatchEvent(event);
};

const buildCommand = () => {
  tooling?.requestPreview("eric-zimmerman", buildPayload);
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
    if (tool.supports_csvf === false) {
      toolOutput.textContent = "Output: CSV files (tool-defined names)";
    } else {
      toolOutput.textContent = `Output: ${tool.csv_name} (CSV)`;
    }
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
  if (runResults) runResults.hidden = true;
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

const buildPayload = () => ({
  tool_id: selectedToolId,
  case_id: caseSelect?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
});

if (tooling) {
  tooling.createRunHandler({
    runButton, runStatus, apiEndpoint: "/api/eric-zimmerman/run", toolName: "parser", buildPayload,
    onStart: () => {
      const tool = toolsById[selectedToolId];
      if (!tool) throw new Error("Select a parser first.");
      if (!tool.installed) throw new Error(`${tool.label} is unavailable.`);
      if (runResults) runResults.hidden = true;
    },
    setRunIdRef: id => { currentRunId = id; },
    onSuccess: data => {
      if (outputPath) outputPath.value = data.output_path;
      if (commandPreview) commandPreview.textContent = data.command;
    },
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
