const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const imagePath = common.imagePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const recursiveFlag = document.getElementById("recursiveFlag");
const extractUnknown = document.getElementById("extractUnknown");
const duplicates = document.getElementById("duplicates");
const runButton = document.getElementById("runExiftool");
const resultOutput = document.getElementById("resultOutput");
const resultCount = document.getElementById("resultCount");
const milestonesList = document.getElementById("milestoneList");

let currentRunId = "";

const getOutputFormat = () => {
  const checked = document.querySelector('input[name="outputFormat"]:checked');
  return checked ? checked.value : "csv";
};

const getSelectedFocus = () => {
  return Array.from(document.querySelectorAll(".chip input:checked")).map(
    (input) => input.value,
  );
};

const buildCommand = () => {
  const format = getOutputFormat();
  const args = ["exiftool"];

  if (format === "json") {
    args.push("-json");
  } else {
    args.push("-csv");
  }

  if (recursiveFlag?.checked) {
    args.push("-r");
  }
  if (extractUnknown?.checked) {
    args.push("-u");
  }
  if (duplicates?.checked) {
    args.push("-a");
  }

  args.push("-G1", "-s");
  args.push(imagePath?.value.trim() || "<source_path>");
  args.push(">", `metadata.${format}`);

  if (commandPreview) {
    commandPreview.textContent = args.join(" ");
  }
};

const buildPayload = () => ({
  tool: "exiftool",
  case_id: caseSelect?.value || "",
  image_path: imagePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  output_format: getOutputFormat(),
  focus: getSelectedFocus(),
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
      // Update file count if available
      const match = (payload.message || "").match(/Processed (\d+) files/);
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
        const format = getOutputFormat();
        resultOutput.textContent = `metadata.${format}`;
      }
    },
  });
}

// Attach input listeners
if (tooling) {
  tooling.attachInputListeners(
    [imagePath, outputPath, recursiveFlag, extractUnknown, duplicates],
    buildCommand,
  );
  tooling.attachChipListeners(".chip input", buildCommand);

  // Handle format radio buttons
  document.querySelectorAll('input[name="outputFormat"]').forEach((radio) => {
    radio.addEventListener("change", buildCommand);
  });
}

buildCommand();
