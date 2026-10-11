const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
const outputPath = common.outputPath;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const recursiveFlag = document.getElementById("recursiveFlag");
const extractUnknown = document.getElementById("extractUnknown");
const duplicates = document.getElementById("duplicates");
const runButton = document.getElementById("runExiftool");
const resultOutput = document.getElementById("resultOutput");
const milestonesList = document.getElementById("milestoneList");

let currentRunId = "";

const getOutputFormat = () => {
  const checked = document.querySelector('input[name="outputFormat"]:checked');
  return checked ? checked.value : "csv";
};

const buildCommand = () => {
  tooling?.requestPreview("exiftool", buildPayload);
};

const buildPayload = () => ({

  case_id: caseSelect?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  output_format: getOutputFormat(),
  recursive: recursiveFlag?.checked || false,
  extract_unknown: extractUnknown?.checked || false,
  duplicates: duplicates?.checked || false,
});

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
    apiEndpoint: "/api/exiftool/run",
    toolName: "ExifTool",
    buildPayload,
    onStart: () => {
      if (milestonesList) {
        milestonesList.innerHTML = "";
      }
    },
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onMilestone: (payload) => {
      appendMilestone(payload.message || "Milestone");
    },
    onSuccess: (data) => {
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
      if (resultOutput) {
        const format = getOutputFormat();
        resultOutput.textContent = `metadata.${format}`;
      }
    },
  });
}

// Attach input listeners
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, recursiveFlag, extractUnknown, duplicates],
    buildCommand,
  );

  // Handle format radio buttons
  document.querySelectorAll('input[name="outputFormat"]').forEach((radio) => {
    radio.addEventListener("change", buildCommand);
  });
}

buildCommand();
