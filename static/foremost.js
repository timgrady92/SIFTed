const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const imagePath = common.imagePath;
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
const resultSummary = document.getElementById("resultSummary");
const runLog = document.getElementById("runLog");
const milestonesList = document.getElementById("milestoneList");

let currentRunId = "";

const mapType = (value) => (value === "jpeg" ? "jpg" : value);

const buildCommand = () => {
  const types = Array.from(document.querySelectorAll(".chip input:checked"))
    .map((input) => mapType(input.value))
    .join(",");

  const args = [
    "foremost",
    "-i",
    imagePath?.value.trim() || "<image_path>",
    "-o",
    outputPath?.value.trim() || "<output_dir>",
  ];

  if (types) {
    args.push("-t", types);
  }
  if (quickFlag?.checked) {
    args.push("-q");
  }
  if (verboseFlag?.checked) {
    args.push("-v");
  }
  if (safeMode?.checked) {
    args.push("-T");
    args.push("# safe mode: 10s per type");
  }

  if (commandPreview) {
    commandPreview.textContent = args.join(" ");
  }
};

const buildPayload = () => ({
  tool: "foremost",
  case_id: caseSelect?.value || "",
  image_path: imagePath?.value.trim() || "",
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
      if (imagePath) {
        imagePath.value = path;
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
        resultAudit.textContent = "audit.txt";
      }
      if (resultSummary) {
        resultSummary.textContent = "output.txt";
      }
    },
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners(
    [imagePath, outputPath, quickFlag, verboseFlag, safeMode],
    buildCommand,
  );
  tooling.attachChipListeners(".chip input", buildCommand);
}

buildCommand();
