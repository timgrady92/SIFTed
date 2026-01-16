const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const imagePath = common.imagePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const runStatus = common.runStatus;

// Tool-specific elements
const timezoneInput = document.getElementById("timelineTimezone");
const runButton = document.getElementById("runTimeline");
const runResults = document.getElementById("runResults");
const runResultsLinks = document.getElementById("runResultsLinks");

let currentRunId = "";

const buildCommand = () => {
  const sourcePath = imagePath?.value.trim() || "<evidence_path>";
  const outputDir = outputPath?.value.trim() || "<output_dir>";
  const timezone = timezoneInput?.value.trim() || "UTC";
  const storagePath = `${outputDir}/timeline.plaso`;
  const timelinePath = `${outputDir}/timeline.csv`;

  const log2timeline = ["log2timeline.py", "--storage_file", storagePath, sourcePath];
  const psort = [
    "psort.py",
    "-o",
    "l2tcsv",
    "-w",
    timelinePath,
    "--output_time_zone",
    timezone,
    storagePath,
  ];

  if (commandPreview) {
    commandPreview.textContent = `${log2timeline.join(" ")} && ${psort.join(" ")}`;
  }
};

const renderResultsLink = (outputDir) => {
  if (!runResults || !runResultsLinks) {
    return;
  }
  if (!outputDir) {
    runResults.hidden = true;
    runResultsLinks.innerHTML = "";
    return;
  }
  const timelinePath = `${outputDir}/timeline.csv`;
  runResultsLinks.innerHTML = "";
  const link = document.createElement("a");
  link.className = "run-result-link";
  link.href = `/view-file?path=${encodeURIComponent(timelinePath)}`;
  link.textContent = "timeline.csv";
  runResultsLinks.appendChild(link);
  runResults.hidden = false;
};

const buildPayload = () => ({
  tool: "artifact-triage",
  case_id: document.getElementById("caseSelect")?.value || "",
  image_path: imagePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  timezone: timezoneInput?.value.trim() || "UTC",
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
    apiEndpoint: "/api/artifact-triage/run",
    toolName: "Timeline",
    buildPayload,
    onStart: () => {
      renderResultsLink("");
    },
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onMilestone: (payload) => {
      if (tooling) {
        tooling.setRunStatus(runStatus, payload.message || "Running...", "neutral");
      }
    },
    onSuccess: (data) => {
      if (commandPreview) {
        commandPreview.textContent = data.command || commandPreview.textContent;
      }
      const resolvedOutputPath = data.output_path || outputPath?.value.trim() || "";
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
      renderResultsLink(resolvedOutputPath);
    },
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners(
    [imagePath, outputPath, timezoneInput],
    buildCommand,
  );
}

buildCommand();
