const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const minLength = document.getElementById("minLength");
const showOffsets = document.getElementById("showOffsets");
const runButton = document.getElementById("runStrings");
const resultOutput = document.getElementById("resultOutput");
const resultCount = document.getElementById("resultCount");

let currentRunId = "";

const getEncoding = () => {
  const checked = document.querySelector('input[name="encoding"]:checked');
  return checked ? checked.value : "s";
};

const buildCommand = () => {
  tooling?.requestPreview("strings", buildPayload);
};

const buildPayload = () => ({

  case_id: caseSelect?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  encoding: getEncoding(),
  min_length: parseInt(minLength?.value || "4", 10),
  show_offsets: showOffsets?.checked || false,
});

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
    apiEndpoint: "/api/strings/run",
    toolName: "Strings",
    buildPayload,
    onStart: () => {},
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onMilestone: (payload) => {
      // Update string count if available
      const match = (payload.message || "").match(/Found (\d+) strings/);
      if (match && resultCount) {
        resultCount.textContent = match[1];
      }
    },
    onSuccess: (data) => {
      if (commandPreview) {
        commandPreview.textContent = data.command || commandPreview.textContent;
      }
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
      if (resultOutput) {
        resultOutput.textContent = "strings.txt";
      }
    },
  });
}

// Attach input listeners
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, minLength, showOffsets],
    buildCommand,
  );

  // Handle encoding radio buttons
  document.querySelectorAll('input[name="encoding"]').forEach((radio) => {
    radio.addEventListener("change", buildCommand);
  });
}

buildCommand();
