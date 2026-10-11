const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
const outputPath = common.outputPath;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const recursiveFlag = document.getElementById("recursiveFlag");
const mismatchOnly = document.getElementById("mismatchOnly");
const runButton = document.getElementById("runFiletype");
const resultOutput = document.getElementById("resultOutput");
const resultCount = document.getElementById("resultCount");
const resultMismatches = document.getElementById("resultMismatches");

let currentRunId = "";

const getMode = () => {
  const checked = document.querySelector('input[name="mode"]:checked');
  return checked ? checked.value : "mime";
};

const buildCommand = () => {
  tooling?.requestPreview("filetype", buildPayload);
};

const buildPayload = () => ({

  case_id: caseSelect?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  mode: getMode(),
  recursive: recursiveFlag?.checked || false,
  mismatch_only: mismatchOnly?.checked || false,
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
    apiEndpoint: "/api/filetype/run",
    toolName: "File Type Detection",
    buildPayload,
    onStart: () => {},
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onMilestone: (payload) => {
      // Update counts if available
      const fileMatch = (payload.message || "").match(/Processed (\d+) files/);
      const mismatchMatch = (payload.message || "").match(/(\d+) mismatches/);
      if (fileMatch && resultCount) {
        resultCount.textContent = fileMatch[1];
      }
      if (mismatchMatch && resultMismatches) {
        resultMismatches.textContent = mismatchMatch[1];
      }
    },
    onSuccess: (data) => {
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
      if (resultOutput) {
        resultOutput.textContent = "filetypes.csv";
      }
    },
  });
}

// Attach input listeners
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, recursiveFlag, mismatchOnly],
    buildCommand,
  );

  // Handle mode radio buttons
  document.querySelectorAll('input[name="mode"]').forEach((radio) => {
    radio.addEventListener("change", buildCommand);
  });
}

buildCommand();
