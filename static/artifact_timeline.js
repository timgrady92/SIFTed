const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
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
  tooling?.requestPreview("artifact-triage", buildPayload);
};

const buildPayload = () => ({

  case_id: document.getElementById("caseSelect")?.value || "",
  source_path: sourcePath?.value.trim() || "",
  output_path: outputPath?.value.trim() || "",
  timezone: timezoneInput?.value.trim() || "UTC",
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
    apiEndpoint: "/api/artifact-triage/run",
    toolName: "Timeline",
    buildPayload,
    onStart: () => {
      if (runResults) runResults.hidden = true;
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
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
    },
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, timezoneInput],
    buildCommand,
  );
}

buildCommand();
