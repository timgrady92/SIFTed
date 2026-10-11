const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const quickFlag = document.getElementById("quickFlag");
const verboseFlag = document.getElementById("verboseFlag");
const safeMode = document.getElementById("safeMode");
const runButton = document.getElementById("runForemost");
const resultCarved = document.getElementById("resultCarved");
const resultAudit = document.getElementById("resultAudit");
const runLog = document.getElementById("runLog");
const milestonesList = document.getElementById("milestoneList");

let currentRunId = "";

const mapType = (value) => (value === "jpeg" ? "jpg" : value);

const buildCommand = () => {
  tooling?.requestPreview("foremost", buildPayload);
};

const buildPayload = () => ({

  case_id: caseSelect?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  types: Array.from(document.querySelectorAll(".chip input:checked")).map(
    (input) => mapType(input.value),
  ),
  quick: quickFlag?.checked || false,
  verbose: verboseFlag?.checked || false,
  safe_mode: safeMode?.checked || false,
});

const setRunLog = (text) => {
  if (runLog) {
    runLog.textContent = text || "";
  }
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

  // Create run handler using factory
  tooling.createRunHandler({
    runButton,
    runStatus,
    apiEndpoint: "/api/foremost/run",
    toolName: "Foremost",
    buildPayload,
    onStart: () => {
      if (milestonesList) {
        milestonesList.innerHTML = "";
      }
      setRunLog("");
    },
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onMilestone: (payload) => {
      appendMilestone(payload.message || "Milestone");
    },
    onSuccess: (data) => {
      if (commandPreview) {
        commandPreview.textContent = data.command || commandPreview.textContent;
      }
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
      if (resultCarved) {
        resultCarved.textContent = `${data.output_path || outputPath?.value}/`;
      }
      if (resultAudit) {
        resultAudit.textContent = safeMode?.checked ? "One audit per selected type" : "audit.txt";
      }
    },
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, quickFlag, verboseFlag, safeMode],
    buildCommand,
  );
  tooling.attachChipListeners(".chip input", buildCommand);
}

buildCommand();
