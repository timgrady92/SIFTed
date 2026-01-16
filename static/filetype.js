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
  const mode = getMode();
  const source = imagePath?.value.trim() || "<source_path>";
  let args = [];

  if (recursiveFlag?.checked) {
    args.push("find", source, "-type", "f", "-exec", "file");
  } else {
    args.push("file");
  }

  if (mode === "mime") {
    args.push("--mime-type", "-b");
  } else if (mode === "brief") {
    args.push("-b");
  }

  if (recursiveFlag?.checked) {
    args.push("{}", "\\;");
  } else {
    args.push(source);
  }

  if (mismatchOnly?.checked) {
    args.push("# filter mismatches");
  }

  if (commandPreview) {
    commandPreview.textContent = args.join(" ");
  }
};

const buildPayload = () => ({
  tool: "filetype",
  case_id: caseSelect?.value || "",
  image_path: imagePath?.value.trim() || "",
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
      if (commandPreview) {
        commandPreview.textContent = data.command || commandPreview.textContent;
      }
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
    [imagePath, outputPath, recursiveFlag, mismatchOnly],
    buildCommand,
  );

  // Handle mode radio buttons
  document.querySelectorAll('input[name="mode"]').forEach((radio) => {
    radio.addEventListener("change", buildCommand);
  });
}

buildCommand();
