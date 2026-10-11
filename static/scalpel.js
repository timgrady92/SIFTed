const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const runButton = document.getElementById("runScalpel");
const organizeByType = document.getElementById("organizeByType");

let currentRunId = "";

const gatherTypes = () => {
  const types = [];
  document.querySelectorAll(".focus-types input:checked").forEach((input) => {
    const typeList = input.dataset.types || "";
    typeList.split(",").forEach((entry) => {
      const trimmed = entry.trim();
      if (trimmed) {
        types.push(trimmed);
      }
    });
  });
  return types;
};

const buildCommand = () => {
  tooling?.requestPreview("scalpel", buildPayload);
};

const buildPayload = () => ({

  case_id: caseSelect?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  types: gatherTypes(),
  organize: organizeByType?.checked ?? true,
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
    apiEndpoint: "/api/scalpel/run",
    toolName: "Scalpel",
    buildPayload,
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onSuccess: (data) => {
      if (commandPreview) {
        commandPreview.textContent = data.command || commandPreview.textContent;
      }
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
    },
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, organizeByType],
    buildCommand,
  );
  tooling.attachChipListeners(".chip input", buildCommand);
}

buildCommand();
