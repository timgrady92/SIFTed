const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const imagePath = common.imagePath;
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
  const types = gatherTypes();
  const args = [
    "scalpel",
    "-c",
    "<generated_config>",
    "-o",
    outputPath?.value.trim() || "<output_dir>",
  ];
  if (!organizeByType?.checked) {
    args.push("-O");
  }
  args.push(imagePath?.value.trim() || "<image_path>");
  if (types.length) {
    args.push(`# ${types.join(", ")}`);
  }
  if (commandPreview) {
    commandPreview.textContent = args.join(" ");
  }
};

const buildPayload = () => ({
  tool: "scalpel",
  case_id: caseSelect?.value || "",
  image_path: imagePath?.value.trim() || "",
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
    [imagePath, outputPath, organizeByType],
    buildCommand,
  );
  tooling.attachChipListeners(".chip input", buildCommand);
}

buildCommand();
